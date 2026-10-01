package zserve

import (
	"context"
	"log"

	"github.com/miekg/dns"

	"dnssvc/internal/zmodel"
)

const streamFlushBytes = 60000

// sendAXFR 流式发送完整区域：首消息以 SOA 开头，主体按名字/类型排序，
// 末消息以收尾 SOA 结束。整个流取自同一个不可变快照，更新期间发起的
// 传送首尾 SOA 序列号必然一致，绝不会看到半个版本。
func (s *Server) sendAXFR(w dns.ResponseWriter, req *dns.Msg, snap *zmodel.Snapshot, t *dns.TSIG) {
	limit := chunkLimit(streamFlushBytes)
	body := snap.AllRecordsRR() // 已排序，第一位是 SOA
	chunks := chunkForStream(body, limit)

	sg := &streamSigner{t: t, w: w}
	for i, chunk := range chunks {
		// 故障注入构建下每块可重读快照；正常构建返回同一 snap。
		cur := s.axfrSnapshot(snap)
		if faultEnabled && cur != snap {
			cb := cur.AllRecordsRR()
			cc := chunkForStream(cb, limit)
			if i < len(cc) {
				chunk = cc[i]
			}
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = chunk
		if i == len(chunks)-1 {
			m.Answer = append(m.Answer, cur.SOA()) // 收尾 SOA
		}
		if err := sg.write(m); err != nil {
			log.Printf("zserve: AXFR 写出失败: %v", err)
			return
		}
	}
}

// sendIXFR 按 RFC 1995 返回增量：
//   - 请求 SOA 序列号 == 当前：只回一条当前 SOA；
//   - 请求序列号能在保留版本中找到：SOA(当前) + 逐版本删除/新增块；
//   - 找不到请求序列号（历史已不可得）：回退为完整 AXFR。
func (s *Server) sendIXFR(w dns.ResponseWriter, req *dns.Msg, snap *zmodel.Snapshot, t *dns.TSIG) {
	// 客户端把“它持有的 SOA”放在 Authority 段（RFC 1995）。
	var clientSerial uint32
	if len(req.Ns) > 0 {
		if soa, ok := req.Ns[0].(*dns.SOA); ok {
			clientSerial = soa.Serial
		}
	} else if len(req.Extra) > 0 {
		// 兼容把 SOA 放在附加段的客户端。
		if soa, ok := req.Extra[0].(*dns.SOA); ok {
			clientSerial = soa.Serial
		}
	}

	// 已经是最新：只返回当前 SOA（单条消息）。
	if clientSerial == snap.Serial {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = []dns.RR{snap.SOA()}
		sg := &streamSigner{t: t, w: w}
		if err := sg.write(m); err != nil {
			log.Printf("zserve: IXFR(up-to-date) 写出失败: %v", err)
		}
		return
	}

	ctx := context.Background()
	base, err := s.store.VersionBySerial(ctx, s.cfg.Zone, clientSerial)
	if err != nil {
		log.Printf("zserve: IXFR 查询基础版本失败: %v", err)
		refuse(w, req)
		return
	}
	if base == nil {
		// 基础版本不可得：标准回退为 AXFR。
		log.Printf("zserve: IXFR 找不到 serial=%d，回退 AXFR", clientSerial)
		s.sendAXFR(w, req, snap, t)
		return
	}

	versions, err := s.store.VersionsBetween(ctx, s.cfg.Zone, base.Version+1)
	if err != nil || len(versions) == 0 {
		log.Printf("zserve: IXFR 版本区间为空: %v", err)
		s.sendAXFR(w, req, snap, t)
		return
	}

	// 构造 IXFR answer：最新 SOA 开头，随后每个版本一个 RFC 1995 变更块。
	var answer []dns.RR
	answer = append(answer, snap.SOA())

	old := mustRRs(base.Records)
	for _, v := range versions {
		newRRs := mustRRs(v.Records)
		oldSOA := soaOf(old)
		newSOA := soaOf(newRRs)
		// 块：旧SOA / 删除的旧RR / 新SOA / 新增的新RR（差异不含 SOA）。
		answer = append(answer, oldSOA)
		answer = append(answer, deletedRRs(old, newRRs)...)
		answer = append(answer, newSOA)
		answer = append(answer, addedRRs(old, newRRs)...)
		old = newRRs
	}
	// RFC 1995：增量序列以当前（最新）SOA 收尾，与开头 SOA 相同。
	answer = append(answer, snap.SOA())

	chunks := chunkForStream(answer, streamFlushBytes)
	sg := &streamSigner{t: t, w: w}
	for _, chunk := range chunks {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = chunk
		if err := sg.write(m); err != nil {
			log.Printf("zserve: IXFR 写出失败: %v", err)
			return
		}
	}
}

// chunkForStream 按打包线长把 RR 序列切成多消息。
// 切分点只在完整 RR 之间；单条记录超长也不会被截断。
func chunkForStream(rrs []dns.RR, limit int) [][]dns.RR {
	var chunks [][]dns.RR
	cur := []dns.RR{}
	curLen := 0
	flush := func() {
		if len(cur) > 0 {
			chunks = append(chunks, cur)
			cur = nil
			curLen = 0
		}
	}
	for _, rr := range rrs {
		l := dns.Len(rr) + 16 // 16 为消息头估算余量
		if curLen+l > limit && len(cur) > 0 {
			flush()
		}
		cur = append(cur, dns.Copy(rr))
		curLen += l
	}
	flush()
	if len(chunks) == 0 {
		chunks = [][]dns.RR{{}}
	}
	return chunks
}
