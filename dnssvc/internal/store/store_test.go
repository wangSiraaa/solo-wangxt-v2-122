package store

import (
	"testing"

	"dnssvc/internal/zmodel"

	"github.com/miekg/dns"
)

func TestDiff(t *testing.T) {
	mk := func(text string) *zmodel.Record {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		return &zmodel.Record{Name: rr.Header().Name, Type: rr.Header().Rrtype, TTL: 3600, Text: text}
	}
	old := []*zmodel.Record{
		mk("home.test.\t3600\tIN\tSOA\tx. 1 3600 900 1209600 3600"), // SOA 不进 diff
		mk("a.home.test.\t3600\tIN\tA\t127.0.0.1"),
		mk("b.home.test.\t3600\tIN\tA\t127.0.0.2"),
	}
	new := []*zmodel.Record{
		mk("home.test.\t3600\tIN\tSOA\tx. 2 3600 900 1209600 3600"),
		mk("b.home.test.\t3600\tIN\tA\t127.0.0.2"),
		mk("c.home.test.\t3600\tIN\tA\t127.0.0.3"),
	}
	ch := Diff(old, new)
	var adds, dels int
	for _, c := range ch {
		switch c.Change {
		case "add":
			adds++
		case "del":
			dels++
		}
	}
	if adds != 1 || dels != 1 {
		t.Fatalf("期望 1 add 1 del（SOA 不计），得到 adds=%d dels=%d %+v", adds, dels, ch)
	}
}
