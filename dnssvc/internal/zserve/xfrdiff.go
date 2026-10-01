package zserve

import (
	"github.com/miekg/dns"

	"dnssvc/internal/zmodel"
)

// mustRRs 把存储记录还原为 RR（快照构建时已保证可解析）。
func mustRRs(recs []*zmodel.Record) []dns.RR {
	out := make([]dns.RR, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.RR())
	}
	return out
}

func soaOf(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return dns.Copy(soa).(*dns.SOA)
		}
	}
	return nil
}

// 以完整 RR 线文本为键计算 IXFR 增量块（排除 SOA，SOA 单独成对出现）。
func deletedRRs(old, new []dns.RR) []dns.RR {
	newSet := map[string]bool{}
	for _, rr := range new {
		if rr.Header().Rrtype != dns.TypeSOA {
			newSet[rr.String()] = true
		}
	}
	var out []dns.RR
	for _, rr := range old {
		if rr.Header().Rrtype == dns.TypeSOA {
			continue
		}
		if !newSet[rr.String()] {
			out = append(out, dns.Copy(rr))
		}
	}
	return out
}

func addedRRs(old, new []dns.RR) []dns.RR {
	oldSet := map[string]bool{}
	for _, rr := range old {
		if rr.Header().Rrtype != dns.TypeSOA {
			oldSet[rr.String()] = true
		}
	}
	var out []dns.RR
	for _, rr := range new {
		if rr.Header().Rrtype == dns.TypeSOA {
			continue
		}
		if !oldSet[rr.String()] {
			out = append(out, dns.Copy(rr))
		}
	}
	return out
}

// supportedRRType 报告查询类型是否在明确支持清单。
func supportedRRType(t uint16) (string, bool) {
	n, ok := zmodel.SupportedTypes[t]
	return n, ok
}
