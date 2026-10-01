package zserve

import (
	"log"
	"net"

	"github.com/miekg/dns"

	"dnssvc/internal/zmodel"
)

// handleDNS 是唯一的查询入口。设计要点：
//   - 只接受标准 QUERY opcode（UPDATE 等直接 REFUSED）；
//   - 查询名必须在本区域之下，否则 REFUSED——绝不向外部名字发起任何动作；
//   - 不提供递归：不设置 RA，对 RD 请求也不会去抓任何外部地址；
//   - AXFR/IXFR 仅 TCP、仅 ACL 客户端、必须带合法 TSIG（库校验）。
func (s *Server) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("zserve: 处理请求时 panic: %v", r)
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
		}
	}()

	if req.Opcode != dns.OpcodeQuery {
		// 只实现标准 QUERY；UPDATE 等其他 opcode 回 NOTIMP。
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNotImplemented)
		_ = w.WriteMsg(m)
		return
	}
	if len(req.Question) != 1 {
		formErr(w, req)
		return
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET {
		formErr(w, req)
		return
	}

	qname := dns.CanonicalName(q.Name)
	if !dns.IsSubDomain(s.cfg.Zone, qname) {
		// 查询区域外名字：拒绝。我们不递归、不转发、不抓取任意外部名字。
		refuse(w, req)
		return
	}

	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		s.handleTransfer(w, req, q)
	default:
		s.handleQuery(w, req, q)
	}
}

// handleQuery 处理普通权威查询。
func (s *Server) handleQuery(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	snap := s.holder.load()

	m := new(dns.Msg)
	m.SetReply(req) // SetReply 会原样回显 RD；我们不设 RA 即表明不提供递归
	m.Authoritative = true

	if snap == nil {
		// 区域尚无任何版本：拒绝，不冒充权威。
		m.Rcode = dns.RcodeRefused
		writeResp(w, m)
		return
	}

	// 不在支持清单内的类型：NOTIMP。
	if _, ok := supportedRRType(q.Qtype); !ok && q.Qtype != dns.TypeANY {
		m.Rcode = dns.RcodeNotImplemented
		writeResp(w, m)
		return
	}

	result := snap.Lookup(q.Name, q.Qtype)
	m.Answer = append(m.Answer, result.Answers...)

	// NXDOMAIN 与 NODATA 的区分以“（链末端）名字是否存在”为准；
	// 经 DNAME/CNAME 重写时 Answer 可能非空但仍为 NXDOMAIN（RFC 6672）。
	if !result.Exists {
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, s.negSOA(snap))
	} else if len(m.Answer) == 0 {
		// 名字存在但无此类型：NODATA，权威 SOA（RFC 2308）。
		m.Rcode = dns.RcodeSuccess
		m.Ns = append(m.Ns, s.negSOA(snap))
	}

	writeResp(w, m)
}

// negSOA 构造负响应权威段 SOA，TTL 取 min(SOA TTL, 配置负缓存上限)。
func (s *Server) negSOA(snap *zmodel.Snapshot) *dns.SOA {
	soa := snap.SOA()
	neg := s.cfg.NegTTL
	if ttl := snap.SOATTL(); ttl < neg {
		neg = ttl
	}
	soa.Hdr.Ttl = neg
	return soa
}

// handleTransfer 处理 AXFR/IXFR。
func (s *Server) handleTransfer(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	// 传送只走 TCP。
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		formErr(w, req)
		return
	}

	host := w.RemoteAddr().(*net.TCPAddr).IP

	// 1) 来源必须在授权 ACL（回环网段）内。
	if !s.acl.Allow(host) {
		log.Printf("zserve: 拒绝未授权传送客户端 %s", host)
		refuse(w, req)
		return
	}

	// 2) 必须携带 TSIG，且密码学校验由 miekg/dns 完成（不自创签名协议）。
	t := req.IsTsig()
	if t == nil {
		log.Printf("zserve: 拒绝无 TSIG 的传送客户端 %s", host)
		refuse(w, req)
		return
	}
	if err := w.TsigStatus(); err != nil {
		log.Printf("zserve: 拒绝 TSIG 校验失败的传送客户端 %s: %v", host, err)
		refuse(w, req)
		return
	}

	snap := s.holder.load()
	if snap == nil || dns.CanonicalName(q.Name) != s.cfg.Zone {
		refuse(w, req)
		return
	}

	if q.Qtype == dns.TypeAXFR {
		s.sendAXFR(w, req, snap, t)
	} else {
		s.sendIXFR(w, req, snap, t)
	}
}

func refuse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	_ = w.WriteMsg(m)
}

func formErr(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeFormatError)
	_ = w.WriteMsg(m)
}

func writeResp(w dns.ResponseWriter, m *dns.Msg) {
	if err := w.WriteMsg(m); err != nil {
		log.Printf("zserve: 写出响应失败: %v", err)
	}
}
