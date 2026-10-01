package zserve

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dnssvc/internal/config"
	"dnssvc/internal/zmodel"
)

// newTestServer 直接构造一个内存快照服务（不需要 PostgreSQL）。
func newTestServer(t *testing.T, recs []*zmodel.Record, tsig bool) (*Server, string) {
	t.Helper()
	snap := zmodel.Build("home.test.", recs)
	cfg := &config.Config{
		Zone:        "home.test.",
		MinTTL:      60,
		MaxTTL:      86400,
		NegTTL:      300,
		TransferACL: []string{"127.0.0.0/8", "::1/128"},
	}
	secret := map[string]string{}
	if tsig {
		cfg.TSIG = map[string]config.TSIGKey{
			"transfer.home.test.": {Algorithm: dns.HmacSHA256, SecretB64: testSecret},
		}
		secret["transfer.home.test."] = testSecret
	}
	acl, err := NewACL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg, holder: &holder{}, acl: acl, secret: secret}
	s.holder.store(snap)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNS)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	s.udp = &dns.Server{PacketConn: pc, Handler: mux, TsigSecret: secret}
	s.tcp = &dns.Server{Listener: ln, Handler: mux, TsigSecret: secret}
	go s.udp.ActivateAndServe()
	go s.tcp.ActivateAndServe()
	t.Cleanup(func() { s.Shutdown() })
	return s, pc.LocalAddr().String()
}

const testSecret = "pMPWtvzpssGBmPQoOlp6x3ciRBs4fdvro7o+NfsR4Fc="

func mkRR(text string) *zmodel.Record {
	rr, err := dns.NewRR(text)
	if err != nil {
		panic(err)
	}
	f := strings.SplitN(text, "\t", 5)
	rd := ""
	if len(f) == 5 {
		rd = f[4]
	}
	h := rr.Header()
	return &zmodel.Record{Name: dns.CanonicalName(h.Name), Type: h.Rrtype, TTL: h.Ttl, Text: text, Rdata: rd}
}

func testZone() []*zmodel.Record {
	return []*zmodel.Record{
		mkRR("home.test.\t3600\tIN\tSOA\tns1.home.test. admin.home.test. 100 3600 900 1209600 3600"),
		mkRR("home.test.\t3600\tIN\tNS\tns1.home.test."),
		mkRR("ns1.home.test.\t3600\tIN\tA\t127.0.0.53"),
		mkRR("www.home.test.\t3600\tIN\tA\t127.0.0.10"),
		mkRR("www.home.test.\t3600\tIN\tA\t127.0.0.11"),
		mkRR("mail.home.test.\t3600\tIN\tA\t127.0.0.25"),
		mkRR("alias.home.test.\t3600\tIN\tCNAME\twww.home.test."),
	}
}

func exchange(t *testing.T, addr string, m *dns.Msg, netw string) *dns.Msg {
	t.Helper()
	c := new(dns.Client)
	c.Net = netw
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("exchange %s: %v", netw, err)
	}
	return resp
}

func TestQueryMultiRecord(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	m := new(dns.Msg)
	m.SetQuestion("www.home.test.", dns.TypeA)
	resp := exchange(t, addr, m, "udp")
	if len(resp.Answer) != 2 {
		t.Fatalf("www 应返回 2 条 A，得到 %d", len(resp.Answer))
	}
	if !resp.Authoritative {
		t.Fatal("应置 AA 位")
	}
}

func TestNXDOMAINHasSOA(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	m := new(dns.Msg)
	m.SetQuestion("nope.home.test.", dns.TypeA)
	resp := exchange(t, addr, m, "udp")
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("期望 NXDOMAIN，得到 %d", resp.Rcode)
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("NXDOMAIN 权威段应有 1 条 SOA，得到 %d", len(resp.Ns))
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Ttl != 300 {
		t.Fatalf("负响应 SOA TTL 应为 negTTL=300，得到 %v", resp.Ns[0])
	}
}

func TestNODATAHasSOA(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	m := new(dns.Msg)
	m.SetQuestion("mail.home.test.", dns.TypeAAAA)
	resp := exchange(t, addr, m, "udp")
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("期望 NODATA(NOERROR,0 answers)，得到 rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("NODATA 权威段应有 SOA，得到 %d", len(resp.Ns))
	}
}

func TestOutOfZoneRefused(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)
	resp := exchange(t, addr, m, "udp")
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("域外查询应 REFUSED，得到 %d", resp.Rcode)
	}
}

func TestUnsupportedTypeNOTIMP(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	m := new(dns.Msg)
	m.SetQuestion("www.home.test.", dns.TypeRRSIG)
	resp := exchange(t, addr, m, "udp")
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("RRSIG 应 NOTIMP，得到 %d", resp.Rcode)
	}
}

func TestAXFRDeniedWithoutTSIG(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	m := new(dns.Msg)
	m.SetAxfr("home.test.")
	resp := exchange(t, addr, m, "tcp")
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("无 TSIG 的 AXFR 应 REFUSED，得到 %d", resp.Rcode)
	}
}

func TestUDPAXFRFormerr(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	m := new(dns.Msg)
	m.SetQuestion("home.test.", dns.TypeAXFR)
	resp := exchange(t, addr, m, "udp")
	if resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("UDP AXFR 应 FORMERR，得到 %d", resp.Rcode)
	}
}

func TestAXFROKWithTSIG(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{"transfer.home.test.": testSecret}
	m := new(dns.Msg)
	m.SetAxfr("home.test.")
	m.SetTsig("transfer.home.test.", dns.HmacSHA256, 300, time.Now().Unix())
	ch, err := tr.In(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	var soas, total int
	for env := range ch {
		if env.Error != nil {
			t.Fatalf("传送错误: %v", env.Error)
		}
		for _, rr := range env.RR {
			total++
			if rr.Header().Rrtype == dns.TypeSOA {
				soas++
			}
		}
	}
	if soas != 2 {
		t.Fatalf("AXFR 应首尾各 1 个 SOA（共2），得到 %d", soas)
	}
	// SOA*2 + NS + ns1A + www*2 + mailA + aliasCNAME = 8
	if total != 8 {
		t.Fatalf("AXFR 记录数应为 8，得到 %d", total)
	}
}

func TestAXFRBadTSIGRejected(t *testing.T) {
	_, addr := newTestServer(t, testZone(), true)
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{"transfer.home.test.": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	m := new(dns.Msg)
	m.SetAxfr("home.test.")
	m.SetTsig("transfer.home.test.", dns.HmacSHA256, 300, time.Now().Unix())
	ch, err := tr.In(m, addr)
	if err != nil {
		// 库层面连接/验签错误也可接受
		return
	}
	for env := range ch {
		if env.Error != nil {
			return // 预期验签失败
		}
		// 收到的若是单条 REFUSED 也算正确
		if len(env.RR) > 0 {
			t.Fatalf("错误 TSIG 不应传出任何区域记录")
		}
	}
}
