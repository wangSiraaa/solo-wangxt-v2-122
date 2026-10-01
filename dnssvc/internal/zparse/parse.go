// Package zparse 解析 RFC 1035 风格的区域文本文件。
//
// 安全约束：
//   - 词法扫描前先做“去掉注释/字符串字面量”的指令预扫描，
//     明确拒绝 $INCLUDE 与 $GENERATE（$INCLUDE 会让解析器读取
//     服务器本地任意文件，本服务绝不能被输入诱导去抓取内容）；
//   - $ORIGIN 只允许等于被发布区域；
//   - 必须显式 $TTL，每条记录最终 TTL 必须落在配置的边界内；
//   - 解析与校验全部在本地内存完成，不产生任何网络/文件外部访问。
package zparse

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"

	"dnssvc/internal/zmodel"
)

// Parse 解析区域文本。zone 为小写 FQDN；min/maxTTL 为允许的 TTL 边界。
func Parse(r io.Reader, zone string, minTTL, maxTTL uint32) ([]*zmodel.Record, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("读取区域文件: %w", err)
	}
	text := string(raw)
	if err := prescanDirectives(text, zone); err != nil {
		return nil, err
	}

	zp := dns.NewZoneParser(strings.NewReader(text), zone, "uploaded-zone")
	zp.SetIncludeAllowed(false) // 库层面双重保险：禁止 $INCLUDE
	zp.SetDefaultTTL(0)         // 不提供隐式默认 TTL，强制 $TTL 显式给出

	var recs []*zmodel.Record
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		if h.Ttl == 0 {
			return nil, fmt.Errorf("记录 %s %s 缺少 TTL（必须先有 $TTL 或显式给出 TTL）",
				h.Name, dns.TypeToString[h.Rrtype])
		}
		if !dns.IsSubDomain(zone, dns.CanonicalName(h.Name)) {
			return nil, fmt.Errorf("拒绝域外记录 %q（区域 %q）", h.Name, zone)
		}

		// 规范化：库的 String() 输出即权威区域文本；重新解析一次确保自洽。
		canon := rr.String()
		if _, err := dns.NewRR(canon); err != nil {
			return nil, fmt.Errorf("记录规范化后无法解析 %q: %w", canon, err)
		}
		recs = append(recs, &zmodel.Record{
			Name:  dns.CanonicalName(h.Name),
			Type:  h.Rrtype,
			TTL:   h.Ttl,
			Text:  canon,
			Rdata: rdataOnly(canon),
		})
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("区域解析失败: %w", err)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("区域文件为空")
	}
	if err := zmodel.ValidateSet(zone, minTTL, maxTTL, recs); err != nil {
		return nil, err
	}
	return recs, nil
}

// rdataOnly 从 "name ttl class type rdata..." 中取出 rdata 段。
func rdataOnly(text string) string {
	// miekg/dns 的 RR.String() 形如 "a.test.\t3600\tIN\tA\t127.0.0.10"
	fields := strings.SplitN(text, "\t", 5)
	if len(fields) == 5 {
		return fields[4]
	}
	fs := strings.Fields(text)
	if len(fs) >= 5 {
		return strings.Join(fs[4:], " ")
	}
	return text
}

// prescanDirectives 在注释/字符串字面量之外查找指令。
func prescanDirectives(text, zone string) error {
	sc := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	sawTTL := false
	for sc.Scan() {
		lineNo++
		line := stripCommentsAndStrings(sc.Text())
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] != '$' {
			continue
		}
		fields := strings.Fields(trimmed)
		dir := strings.ToUpper(fields[0])
		switch dir {
		case "$TTL":
			if len(fields) < 2 {
				return fmt.Errorf("第 %d 行: $TTL 缺少参数", lineNo)
			}
			d, err := parseTTL(fields[1])
			if err != nil {
				return fmt.Errorf("第 %d 行: 非法 $TTL %q: %w", lineNo, fields[1], err)
			}
			if d < 30 {
				return fmt.Errorf("第 %d 行: $TTL 不得低于 30 秒", lineNo)
			}
			sawTTL = true
		case "$ORIGIN":
			if len(fields) < 2 {
				return fmt.Errorf("第 %d 行: $ORIGIN 缺少参数", lineNo)
			}
			o := dns.CanonicalName(fields[1])
			if o != zone {
				return fmt.Errorf("第 %d 行: $ORIGIN %q 必须等于区域 %q（禁止改写到区域外）",
					lineNo, fields[1], zone)
			}
		case "$INCLUDE":
			return fmt.Errorf("第 %d 行: 禁止 $INCLUDE（本服务不读取外部文件）", lineNo)
		case "$GENERATE":
			return fmt.Errorf("第 %d 行: 禁止 $GENERATE", lineNo)
		default:
			return fmt.Errorf("第 %d 行: 未知或禁止的指令 %s", lineNo, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if !sawTTL {
		return fmt.Errorf("区域文件必须包含 $TTL 指令")
	}
	return nil
}

// stripCommentsAndStrings 移除 RFC 1035 行注释与双引号字面量，
// 使伪造在字符串/注释里的 "$INCLUDE" 不会被当真，反之亦然。
func stripCommentsAndStrings(line string) string {
	var b strings.Builder
	inStr := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inStr = !inStr
			b.WriteByte(' ')
		case c == '\\':
			// 转义字符（含 \"），连同下一字节一并抹掉。
			b.WriteByte(' ')
			if i+1 < len(line) {
				b.WriteByte(' ')
				i++
			}
		case c == ';' && !inStr:
			return b.String()
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// parseTTL 解析纯秒数（"3600"）或 BIND 风格时间（"1h30m"、"1d"）。
// 支持后缀 s/m/h/d/w；不允许负数与溢出。
func parseTTL(s string) (uint32, error) {
	var total uint64
	num := uint64(0)
	haveNum := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			num = num*10 + uint64(c-'0')
			haveNum = true
			if num > uint64(^uint32(0)) {
				return 0, fmt.Errorf("TTL 过大")
			}
			continue
		}
		if !haveNum {
			return 0, fmt.Errorf("数字与后缀格式错误")
		}
		mult := uint64(1)
		switch c {
		case 's', 'S':
			mult = 1
		case 'm', 'M':
			mult = 60
		case 'h', 'H':
			mult = 3600
		case 'd', 'D':
			mult = 86400
		case 'w', 'W':
			mult = 604800
		default:
			return 0, fmt.Errorf("未知 TTL 后缀 %q", c)
		}
		total += num * mult
		num = 0
		haveNum = false
		if total > uint64(^uint32(0)) {
			return 0, fmt.Errorf("TTL 过大")
		}
	}
	if haveNum {
		total += num // 无后缀视为秒
	}
	if total > uint64(^uint32(0)) {
		return 0, fmt.Errorf("TTL 过大")
	}
	return uint32(total), nil
}
