package zmodel

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// baseRecords 构造一个合法最小区域。
func baseRecords(serial uint32) []*Record {
	return []*Record{
		mkRec("home.test.\t3600\tIN\tSOA\tns1.home.test. admin.home.test. " + utoa(uint64(serial)) + " 1h 15m 2w 1h"),
		mkRec("home.test.\t3600\tIN\tNS\tns1.home.test."),
		mkRec("ns1.home.test.\t3600\tIN\tA\t127.0.0.53"),
	}
}

func mkRec(text string) *Record {
	rr := mustRR(text)
	h := rr.Header()
	rd := ""
	if f := strings.SplitN(text, "\t", 5); len(f) == 5 {
		rd = f[4]
	}
	return &Record{Name: dns.CanonicalName(h.Name), Type: h.Rrtype, TTL: h.Ttl, Text: text, Rdata: rd}
}

func mustRR(text string) dns.RR {
	rr, err := dns.NewRR(text)
	if err != nil {
		panic(err)
	}
	return rr
}

func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for v > 0 {
		p--
		b[p] = byte('0' + v%10)
		v /= 10
	}
	return string(b[p:])
}

func TestValidateOK(t *testing.T) {
	if err := ValidateSet("home.test.", 60, 86400, baseRecords(1)); err != nil {
		t.Fatalf("合法区域被拒绝: %v", err)
	}
}

func TestCNAMEConflict(t *testing.T) {
	r := baseRecords(1)
	r = append(r,
		mkRec("www.home.test.\t3600\tIN\tCNAME\tother.home.test."),
		mkRec("www.home.test.\t3600\tIN\tA\t127.0.0.9"))
	err := ValidateSet("home.test.", 60, 86400, r)
	if err == nil || !strings.Contains(err.Error(), "CNAME 冲突") {
		t.Fatalf("期望 CNAME 冲突错误，得到 %v", err)
	}
}

func TestCNAMEAtApex(t *testing.T) {
	r := baseRecords(1)
	r = append(r, mkRec("home.test.\t3600\tIN\tCNAME\telsewhere.example.net."))
	err := ValidateSet("home.test.", 60, 86400, r)
	if err == nil || !strings.Contains(err.Error(), "顶点") {
		t.Fatalf("期望顶点 CNAME 错误，得到 %v", err)
	}
}

func TestOutOfZoneRejected(t *testing.T) {
	r := baseRecords(1)
	r = append(r, mkRec("evil.example.org.\t3600\tIN\tA\t203.0.113.9"))
	err := ValidateSet("home.test.", 60, 86400, r)
	if err == nil || !strings.Contains(err.Error(), "域外") {
		t.Fatalf("期望域外记录错误，得到 %v", err)
	}
}

func TestTTLBounds(t *testing.T) {
	low := append(baseRecords(1), mkRec("low.home.test.\t30\tIN\tA\t127.0.0.1"))
	if err := ValidateSet("home.test.", 60, 86400, low); err == nil {
		t.Fatal("TTL=30 低于下限 60，应被拒绝")
	}
	high := append(baseRecords(1), mkRec("high.home.test.\t90000\tIN\tA\t127.0.0.2"))
	if err := ValidateSet("home.test.", 60, 86400, high); err == nil {
		t.Fatal("TTL=90000 高于上限 86400，应被拒绝")
	}
	boundaryMin := append(baseRecords(1), mkRec("ok.home.test.\t60\tIN\tA\t127.0.0.3"))
	if err := ValidateSet("home.test.", 60, 86400, boundaryMin); err != nil {
		t.Fatalf("TTL=60 恰好在下限边界，应通过: %v", err)
	}
}

func TestMultiRecordSameNameAllowed(t *testing.T) {
	r := baseRecords(1)
	r = append(r,
		mkRec("www.home.test.\t3600\tIN\tA\t127.0.0.10"),
		mkRec("www.home.test.\t3600\tIN\tA\t127.0.0.11"),
		mkRec("home.test.\t3600\tIN\tMX\t10 mail.home.test."),
		mkRec("home.test.\t3600\tIN\tMX\t20 mail2.home.test."))
	if err := ValidateSet("home.test.", 60, 86400, r); err != nil {
		t.Fatalf("同名多记录应允许: %v", err)
	}
	snap := Build("home.test.", r)
	res := snap.Lookup("www.home.test.", dns.TypeA)
	if len(res.Answers) != 2 {
		t.Fatalf("www 应有 2 条 A，得到 %d", len(res.Answers))
	}
}

func TestDuplicateRecordRejected(t *testing.T) {
	r := append(baseRecords(1),
		mkRec("www.home.test.\t3600\tIN\tA\t127.0.0.10"),
		mkRec("www.home.test.\t3600\tIN\tA\t127.0.0.10"))
	if err := ValidateSet("home.test.", 60, 86400, r); err == nil {
		t.Fatal("完全重复记录应被拒绝")
	}
}

func TestUnsupportedTypeRejected(t *testing.T) {
	r := append(baseRecords(1), mkRec("x.home.test.\t3600\tIN\tRRSIG\tA 8 2 3600 20300101000000 20260101000000 12345 home.test. AA=="))
	err := ValidateSet("home.test.", 60, 86400, r)
	// 上面 RRSIG rdata 可能不合法；无论如何它要么解析失败要么类型不被支持。
	if err != nil {
		return
	}
	t.Fatal("RRSIG 不在支持清单，应被拒绝")
}

func TestCNAMEChainAndNODATA(t *testing.T) {
	r := baseRecords(1)
	r = append(r,
		mkRec("alias.home.test.\t3600\tIN\tCNAME\twww.home.test."),
		mkRec("www.home.test.\t3600\tIN\tA\t127.0.0.10"),
		mkRec("mail.home.test.\t3600\tIN\tA\t127.0.0.25"))
	snap := Build("home.test.", r)

	res := snap.Lookup("alias.home.test.", dns.TypeA)
	if len(res.Answers) != 2 {
		t.Fatalf("CNAME 链应返回 CNAME+A 共 2 条，得到 %d", len(res.Answers))
	}
	// mail 存在但没有 AAAA -> NODATA（Exists=true，无答案）。
	res = snap.Lookup("mail.home.test.", dns.TypeAAAA)
	if !res.Exists || len(res.Answers) != 0 {
		t.Fatalf("mail AAAA 应为 NODATA(exists=true,0 answers)，得到 %+v", res)
	}
	// 不存在的名字 -> NXDOMAIN。
	res = snap.Lookup("nope.home.test.", dns.TypeA)
	if res.Exists {
		t.Fatal("nope 应不存在")
	}
}

func TestCNAMEOutOfZoneStops(t *testing.T) {
	r := append(baseRecords(1),
		mkRec("ext.home.test.\t3600\tIN\tCNAME\telsewhere.example.net."))
	snap := Build("home.test.", r)
	res := snap.Lookup("ext.home.test.", dns.TypeA)
	if !res.Exists || len(res.Answers) != 1 {
		t.Fatalf("域外 CNAME 应只返回 1 条 CNAME 并停止，得到 %+v", res)
	}
}

func TestDNAME(t *testing.T) {
	r := append(baseRecords(1),
		mkRec("old.home.test.\t3600\tIN\tDNAME\tnew.home.test."),
		mkRec("x.new.home.test.\t3600\tIN\tA\t127.0.0.77"))
	snap := Build("home.test.", r)
	res := snap.Lookup("x.old.home.test.", dns.TypeA)
	if len(res.Answers) != 3 {
		t.Fatalf("DNAME 查询应返回 DNAME+合成CNAME+A 共 3 条，得到 %d: %v", len(res.Answers), res.Answers)
	}
}
