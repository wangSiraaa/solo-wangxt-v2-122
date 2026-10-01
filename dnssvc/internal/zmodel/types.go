// Package zmodel 定义区域记录模型、记录级校验规则以及不可变的区域快照。
//
// 快照一旦构建即只读；服务端通过整体替换快照指针完成“原子发布”，
// 查询过程中不会看到半个版本。
package zmodel

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/miekg/dns"
)

// SupportedTypes 是本服务明确支持的记录类型。
// 该清单之外的类型在区域载入时拒绝，在查询时返回 NOTIMP。
var SupportedTypes = map[uint16]string{
	dns.TypeSOA:   "SOA",
	dns.TypeNS:    "NS",
	dns.TypeA:     "A",
	dns.TypeAAAA:  "AAAA",
	dns.TypeCNAME: "CNAME",
	dns.TypeDNAME: "DNAME",
	dns.TypeMX:    "MX",
	dns.TypeTXT:   "TXT",
	dns.TypeSRV:   "SRV",
	dns.TypeCAA:   "CAA",
	dns.TypePTR:   "PTR",
}

// Record 是一条已标准化的资源记录。Text 是与库解析结果一致的
// 规范区域文本（FQDN、小写域名、统一转义），随时可用 dns.NewRR 重建。
type Record struct {
	Name  string `json:"name"` // 小写 FQDN
	Type  uint16 `json:"type"`
	TTL   uint32 `json:"ttl"`
	Text  string `json:"text"`  // 完整 RR 规范文本，如 "a.test. 3600 IN A 127.0.0.10"
	Rdata string `json:"rdata"` // 纯 rdata 部分（便于 IXFR 比对/展示）
}

// RR 使用 miekg/dns 解析回内存 RR。存储文本在写入前已校验过可解析。
func (r Record) RR() dns.RR {
	rr, err := dns.NewRR(r.Text)
	if err != nil {
		panic(fmt.Sprintf("内部错误：存储的记录无法解析: %q: %v", r.Text, err))
	}
	return rr
}

// ValidateSet 对一批将构成同一版本的记录做记录级与集合级校验。
// zone 为小写 FQDN；minTTL/maxTTL 为允许的 TTL 闭区间。
// 返回按规范排序后的记录（SOA 在前），或拒绝原因。
func ValidateSet(zone string, minTTL, maxTTL uint32, recs []*Record) error {
	if minTTL == 0 || maxTTL < minTTL {
		return fmt.Errorf("TTL 边界配置非法")
	}

	// 1) 逐条校验
	byName := map[string]map[uint16][]*Record{}
	soaCount := 0
	var soaSerial uint32
	for _, r := range recs {
		rr, err := dns.NewRR(r.Text)
		if err != nil {
			return fmt.Errorf("记录无法解析 %q: %w", r.Text, err)
		}
		h := rr.Header()
		typ := h.Rrtype
		if _, ok := SupportedTypes[typ]; !ok {
			return fmt.Errorf("不支持的记录类型 %d（%s），仅支持明确清单内的类型",
				typ, dns.TypeToString[typ])
		}
		if h.Class != dns.ClassINET {
			return fmt.Errorf("只支持 IN 类记录: %q", r.Text)
		}
		if dns.CanonicalName(h.Name) != r.Name {
			return fmt.Errorf("内部不一致：记录名 %q != %q", h.Name, r.Name)
		}
		if !dns.IsSubDomain(zone, r.Name) {
			return fmt.Errorf("拒绝域外记录: %q 不属于区域 %q", r.Name, zone)
		}
		// 明确拒绝通配符属主（本测试服务不实现通配匹配）。
		if len(r.Name) > 0 && r.Name[0] == '*' {
			return fmt.Errorf("拒绝通配符记录: %q", r.Name)
		}
		if h.Ttl < minTTL || h.Ttl > maxTTL {
			return fmt.Errorf("TTL %d 越界 [%d,%d]: %s", h.Ttl, minTTL, maxTTL, r.Name)
		}
		if typ == dns.TypeSOA {
			soaCount++
			if r.Name != zone {
				return fmt.Errorf("SOA 必须位于区域顶点 %q，实际 %q", zone, r.Name)
			}
			soaSerial = rr.(*dns.SOA).Serial
		}
		if typ == dns.TypeNS {
			if r.Name != zone {
				return fmt.Errorf("拒绝非顶点 NS 记录 %q（不做委派）", r.Name)
			}
			if err := validateRdataInZone(zone, rr); err != nil {
				return err
			}
		}
		if typ == dns.TypeCNAME || typ == dns.TypeDNAME {
			if err := validateRdataInZone(zone, rr); err != nil {
				return err
			}
		}
		if typ == dns.TypeA {
			ip, ok := netip.AddrFromSlice(rr.(*dns.A).A)
			if !ok || !ip.Unmap().Is4() {
				return fmt.Errorf("A 记录地址非法: %q", r.Text)
			}
		}
		if typ == dns.TypeAAAA {
			a16 := rr.(*dns.AAAA).AAAA
			if _, ok := netip.AddrFromSlice(a16); !ok || len(a16) != 16 {
				return fmt.Errorf("AAAA 记录地址非法: %q", r.Text)
			}
		}

		if byName[r.Name] == nil {
			byName[r.Name] = map[uint16][]*Record{}
		}
		byName[r.Name][typ] = append(byName[r.Name][typ], r)
	}

	// 2) 集合级校验
	if soaCount != 1 {
		return fmt.Errorf("区域必须恰好包含 1 条 SOA，实际 %d 条", soaCount)
	}
	nss := byName[zone][dns.TypeNS]
	if len(nss) == 0 {
		return fmt.Errorf("区域顶点必须至少有 1 条 NS 记录")
	}
	_ = soaSerial

	for name, types := range byName {
		if _, hasDNAME := types[dns.TypeDNAME]; hasDNAME && name == zone {
			return fmt.Errorf("DNAME 不允许位于区域顶点（RFC 6672）")
		}
		if _, hasCNAME := types[dns.TypeCNAME]; hasCNAME {
			if len(types[dns.TypeCNAME]) > 1 {
				return fmt.Errorf("%s 存在多条 CNAME", name)
			}
			// CNAME 与任何其他类型同名即冲突（含顶点）。
			if name == zone {
				return fmt.Errorf("CNAME 冲突: 区域顶点 %q 不允许 CNAME", name)
			}
			for t := range types {
				if t != dns.TypeCNAME {
					return fmt.Errorf("CNAME 冲突: %q 同时存在 CNAME 与 %s",
						name, dns.TypeToString[t])
				}
			}
		}
		// 同名同类型允许多条记录（多值 RRset），但完全重复的记录拒绝。
		for t, rs := range types {
			seen := map[string]bool{}
			for _, r := range rs {
				if seen[r.Text] {
					return fmt.Errorf("完全重复的记录: %q", r.Text)
				}
				seen[r.Text] = true
			}
			_ = t
		}
	}
	return nil
}

// validateRdataInZone 校验“必须指向区域内/在本区域内有意义”的 rdata。
// 注意：普通 CNAME 目标本身不强制在区内（CNAME 可以指向任意外部名字，
// 这不会导致服务器去抓取任何内容——我们只返回记录），但 NS 名字服务器
// 必须在区内（本服务不做委派/胶水），因此只对 NS 收紧。
func validateRdataInZone(zone string, rr dns.RR) error {
	if ns, ok := rr.(*dns.NS); ok {
		t := dns.CanonicalName(ns.Ns)
		if !dns.IsSubDomain(zone, t) {
			return fmt.Errorf("拒绝域外 NS 目标 %q（顶点 NS 必须指向区域内名字服务器）", t)
		}
	}
	// 同名 CNAME 自循环无意义，直接拒绝。
	if c, ok := rr.(*dns.CNAME); ok {
		if dns.CanonicalName(c.Target) == dns.CanonicalName(rr.Header().Name) {
			return fmt.Errorf("CNAME 自循环: %q", c.Target)
		}
	}
	return nil
}

// SortRecords 返回 AXFR/存储使用的规范顺序：
// SOA、顶点 NS（及其 A/AAAA 胶水在前），其余按名字、类型权重、rdata 排序。
func SortRecords(recs []*Record) []*Record {
	out := make([]*Record, len(recs))
	copy(out, recs)
	weight := func(t uint16) int {
		switch t {
		case dns.TypeSOA:
			return 0
		case dns.TypeNS:
			return 1
		case dns.TypeA:
			return 2
		case dns.TypeAAAA:
			return 3
		default:
			return 10
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		// SOA 永远第一，收尾 SOA 由传送层自行追加。
		if a.Type == dns.TypeSOA {
			return true
		}
		if b.Type == dns.TypeSOA {
			return false
		}
		if a.Name != b.Name {
			return dns.CanonicalName(a.Name) < dns.CanonicalName(b.Name)
		}
		wa, wb := weight(a.Type), weight(b.Type)
		if wa != wb {
			return wa < wb
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Rdata < b.Rdata
	})
	return out
}
