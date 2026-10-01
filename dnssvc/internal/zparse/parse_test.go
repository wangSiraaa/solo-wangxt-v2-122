package zparse

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	z := `$ORIGIN home.test.
$TTL 3600
@ IN SOA ns1.home.test. admin.home.test. 1 1h 15m 2w 1h
@ IN NS ns1.home.test.
ns1 IN A 127.0.0.53
www IN A 127.0.0.10
www IN A 127.0.0.11
`
	recs, err := Parse(strings.NewReader(z), "home.test.", 60, 86400)
	if err != nil {
		t.Fatalf("合法区域解析失败: %v", err)
	}
	if len(recs) != 5 {
		t.Fatalf("期望 5 条记录，得到 %d", len(recs))
	}
}

func TestIncludeRejected(t *testing.T) {
	z := `$TTL 3600
@ IN SOA ns1.home.test. admin.home.test. 1 1h 15m 2w 1h
@ IN NS ns1.home.test.
$INCLUDE /etc/passwd
`
	if _, err := Parse(strings.NewReader(z), "home.test.", 60, 86400); err == nil {
		t.Fatal("$INCLUDE 必须被拒绝")
	}
}

func TestIncludeInCommentIsFine(t *testing.T) {
	z := `$TTL 3600
@ IN SOA ns1.home.test. admin.home.test. 1 1h 15m 2w 1h
@ IN NS ns1.home.test.
; $INCLUDE /etc/passwd
ns1 IN A 127.0.0.53
`
	if _, err := Parse(strings.NewReader(z), "home.test.", 60, 86400); err != nil {
		t.Fatalf("注释里的 $INCLUDE 不应触发拒绝: %v", err)
	}
}

func TestGenerateRejected(t *testing.T) {
	z := `$TTL 3600
$GENERATE 1-100 host$ IN A 127.0.0.$
@ IN SOA ns1.home.test. admin.home.test. 1 1h 15m 2w 1h
@ IN NS ns1.home.test.
`
	if _, err := Parse(strings.NewReader(z), "home.test.", 60, 86400); err == nil {
		t.Fatal("$GENERATE 必须被拒绝")
	}
}

func TestMissingTTL(t *testing.T) {
	z := `$ORIGIN home.test.
@ IN SOA ns1.home.test. admin.home.test. 1 1h 15m 2w 1h
@ IN NS ns1.home.test.
`
	if _, err := Parse(strings.NewReader(z), "home.test.", 60, 86400); err == nil {
		t.Fatal("缺少 $TTL 必须被拒绝")
	}
}

func TestParseTTLDurations(t *testing.T) {
	cases := map[string]uint32{
		"3600": 3600, "1h": 3600, "1h30m": 5400, "1d": 86400, "2w": 1209600, "90s": 90,
	}
	for in, want := range cases {
		got, err := parseTTL(in)
		if err != nil || got != want {
			t.Errorf("parseTTL(%q)=%d,%v 期望 %d", in, got, err, want)
		}
	}
	if _, err := parseTTL("100000000000"); err == nil {
		t.Error("溢出 TTL 应报错")
	}
}
