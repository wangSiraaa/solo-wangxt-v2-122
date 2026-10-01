package zmodel

import (
	"sort"

	"github.com/miekg/dns"
)

// LookupResult 是一次权威查询的结果。
type LookupResult struct {
	Answers []dns.RR // Answer 段：DNAME+合成CNAME/CNAME 链与终端 RRset
	Exists  bool     // qname 或链末端名字是否存在（区分 NXDOMAIN/NODATA）
}

// Snapshot 是一个已发布版本的不可变内存视图。
// 所有 map/slice 在 Build 之后不再修改，查询无锁读取即可；
// 发布 = 整体替换 *Snapshot 指针，因此查询不可能读到半个版本。
type Snapshot struct {
	Zone    string
	Serial  uint32
	Records []*Record // 规范顺序（含 SOA）

	byNameType map[string]map[uint16][]*Record
	byName     map[string][]*Record
	soa        *dns.SOA
	soaTTL     uint32
	nsRRs      []dns.RR
}

// Build 从已通过 ValidateSet 校验的记录构造快照。
func Build(zone string, recs []*Record) *Snapshot {
	s := &Snapshot{
		Zone:       zone,
		Records:    SortRecords(recs),
		byNameType: map[string]map[uint16][]*Record{},
		byName:     map[string][]*Record{},
	}
	for _, r := range s.Records {
		rr := r.RR()
		if soa, ok := rr.(*dns.SOA); ok {
			s.soa = soa
			s.soaTTL = r.TTL
			s.Serial = soa.Serial
		}
		if r.Type == dns.TypeNS {
			s.nsRRs = append(s.nsRRs, rr)
		}
		if s.byNameType[r.Name] == nil {
			s.byNameType[r.Name] = map[uint16][]*Record{}
		}
		s.byNameType[r.Name][r.Type] = append(s.byNameType[r.Name][r.Type], r)
		s.byName[r.Name] = append(s.byName[r.Name], r)
	}
	// RRset 内部按 rdata 排序，保证多记录响应顺序稳定。
	for n := range s.byNameType {
		for t := range s.byNameType[n] {
			rs := s.byNameType[n][t]
			sort.Slice(rs, func(i, j int) bool { return rs[i].Rdata < rs[j].Rdata })
		}
	}
	return s
}

// SOA 返回 SOA RR 副本。
func (s *Snapshot) SOA() *dns.SOA { return dns.Copy(s.soa).(*dns.SOA) }

// SOATTL 返回 SOA 自身 TTL。
func (s *Snapshot) SOATTL() uint32 { return s.soaTTL }

// NsRRs 返回顶点 NS RR 副本。
func (s *Snapshot) NsRRs() []dns.RR {
	out := make([]dns.RR, len(s.nsRRs))
	for i, rr := range s.nsRRs {
		out[i] = dns.Copy(rr)
	}
	return out
}

// Exists 报告名字是否存在（任何类型）。
func (s *Snapshot) Exists(name string) bool {
	_, ok := s.byName[name]
	return ok
}

// Lookup 返回 qname/qtype 的权威查询结果，遵循 DNAME(RFC 6672) 与
// CNAME(RFC 1034) 链。链中加入的每条记录都取自不可变快照的副本。
func (s *Snapshot) Lookup(qname string, qtype uint16) LookupResult {
	qname = dns.CanonicalName(qname)
	if qtype == dns.TypeANY {
		var out []dns.RR
		for _, r := range s.byName[qname] {
			out = append(out, dns.Copy(r.RR()))
		}
		return LookupResult{Answers: out, Exists: len(out) > 0}
	}

	var answers []dns.RR
	rewritten := false // 是否发生过 DNAME 合成或 CNAME 跟随

	// DNAME 合成：查 qname 的最近祖先（不含顶点的 NS/SOA 查询）。
	if qtype != dns.TypeDNAME && qtype != dns.TypeNS && qtype != dns.TypeSOA {
		if synName, dn, syn, ok := s.applyDNAME(qname); ok {
			answers = append(answers, dns.Copy(dn), syn)
			qname = synName
			rewritten = true
		}
	}

	visited := map[string]bool{}
	for {
		if rs := s.rrset(qname, qtype); len(rs) > 0 {
			for _, r := range rs {
				answers = append(answers, dns.Copy(r.RR()))
			}
			return LookupResult{Answers: answers, Exists: true}
		}
		// CNAME 跟随（显式查 CNAME 时不跟随）。
		if qtype != dns.TypeCNAME {
			if c := s.rrset(qname, dns.TypeCNAME); len(c) > 0 {
				cn := c[0].RR().(*dns.CNAME)
				target := dns.CanonicalName(cn.Target)
				answers = append(answers, dns.Copy(cn))
				// 目标超出本区域：权威服务到此为止，只返回 CNAME（NOERROR）。
				// 绝不向外部名字发起递归/抓取（RFC 1034 3.6.1）。
				if !dns.IsSubDomain(s.Zone, target) {
					return LookupResult{Answers: answers, Exists: true}
				}
				if visited[qname] {
					return LookupResult{Answers: answers, Exists: true} // CNAME 环
				}
				visited[qname] = true
				qname = target
				rewritten = true
				continue
			}
		}
		terminalExists := s.Exists(qname)
		// 经 DNAME/CNAME 重写后，末端名字不存在 = NXDOMAIN
		//（DNAME/CNAME 已在 Answer 中）；名字存在但无此类型 = NODATA。
		// 没有发生重写时，名字是否存在直接决定 NXDOMAIN/NODATA。
		if rewritten && !terminalExists {
			return LookupResult{Answers: answers, Exists: false}
		}
		return LookupResult{Answers: answers, Exists: terminalExists}
	}
}

// applyDNAME 按 RFC 6672 检查祖先 DNAME。返回：
// 合成后的名字、DNAME RR 副本、合成的 CNAME RR、是否命中。
func (s *Snapshot) applyDNAME(qname string) (string, dns.RR, *dns.CNAME, bool) {
	for _, off := range dns.Split(qname) {
		suffix := qname[off:]
		if d := s.rrset(suffix, dns.TypeDNAME); len(d) > 0 {
			dn := d[0].RR().(*dns.DNAME)
			target := dns.CanonicalName(dn.Target)
			prefix := qname[:off] // qname = prefix + DNAME owner
			syn := dns.Fqdn(prefix + target)
			cn := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: dn.Hdr.Ttl},
				Target: syn,
			}
			return syn, dns.Copy(dn), cn, true
		}
	}
	return "", nil, nil, false
}

func (s *Snapshot) rrset(name string, typ uint16) []*Record {
	if m, ok := s.byNameType[name]; ok {
		return m[typ]
	}
	return nil
}

// AllRecordsRR 返回全部记录 RR 副本（AXFR 主体，含首个 SOA，不含收尾 SOA）。
func (s *Snapshot) AllRecordsRR() []dns.RR {
	out := make([]dns.RR, 0, len(s.Records)+1)
	for _, r := range s.Records {
		out = append(out, dns.Copy(r.RR()))
	}
	return out
}
