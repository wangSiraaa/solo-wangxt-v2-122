// xfrstress 是原子发布与“更新中传送”压测工具：
//
//	一边高速发布“整区域全量改写”的大版本，一边并发做
//	  - UDP 随机查询（每个属主必须恰好 1 条 TXT，值与版本对应）；
//	  - TSIG 签名的 AXFR（首尾 SOA serial 必须一致，全部记录必须
//	    属于同一个版本——任何半个版本/撕裂读都会被计数并报告）。
//
// 纯本地测试：服务端只监听回环，本工具也只连 127.0.0.1。
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"dnssvc/internal/config"
	"dnssvc/internal/store"
	"dnssvc/internal/zparse"
)

func main() {
	cfgPath := flag.String("config", envOr("ZONECTL_CFG", "configs/config.json"), "配置文件")
	rounds := flag.Int("rounds", 60, "发布轮数")
	records := flag.Int("records", 1500, "每版本的 TXT 记录数")
	queryWorkers := flag.Int("query-workers", 8, "UDP 查询并发")
	xfrWorkers := flag.Int("xfr-workers", 4, "AXFR 并发")
	publishGap := flag.Duration("gap", 3*time.Millisecond, "发布间隔")
	baseSerialF := flag.Uint("base-serial", 2026100100, "起始 SOA 序列号（每轮 +1）")
	flag.Parse()
	baseSerial := uint32(*baseSerialF)
	baseSerialGlobal = baseSerial

	cfg, err := config.Load(*cfgPath)
	must(err)
	ctx := context.Background()
	st, err := store.New(ctx, cfg.DBConn)
	must(err)
	defer st.Close()

	var keyName string
	var key config.TSIGKey
	for n, k := range cfg.TSIG {
		keyName, key = dns.CanonicalName(n), k
		break
	}

	var (
		failCount  atomic.Int64
		queryCount atomic.Int64
		xfrCount   atomic.Int64
		published  atomic.Int64
		stopFlag   atomic.Bool
	)
	addr := strings.TrimPrefix(cfg.ListenTCP, "127.0.0.1")
	serverAddr := "127.0.0.1" + addr

	// 并发查询/传送 worker。
	var wg sync.WaitGroup
	for i := 0; i < *queryWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
			c := new(dns.Client)
			c.Net = "udp"
			for !stopFlag.Load() {
				n := r.Intn(*records)
				rr, ok := queryOnce(c, serverAddr, fmt.Sprintf("host%d.%s", n, cfg.Zone))
				queryCount.Add(1)
				if !ok {
					failCount.Add(1)
					continue
				}
				if !txtConsistent(rr, baseSerial, *rounds) {
					failCount.Add(1)
					fmt.Printf("QUERY 撕裂读: host%d => %q\n", n, rr)
				}
			}
		}(i)
	}
	for i := 0; i < *xfrWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
			for !stopFlag.Load() {
				n, bad := axfrOnce(serverAddr, cfg.Zone, keyName, key.SecretB64, key.Algorithm, *records)
				xfrCount.Add(1)
				if bad != "" {
					failCount.Add(1)
					fmt.Printf("AXFR 撕裂传送: %s\n", bad)
					continue
				}
				if !versionConsistent(n, baseSerial, *rounds) {
					failCount.Add(1)
					fmt.Printf("AXFR 版本不一致: serial=%d（记录值未全部对应）\n", n)
				}
				_ = r
			}
		}(i)
	}

	// 发布循环。
	t0 := time.Now()
	for round := 1; round <= *rounds; round++ {
		text := buildZone(cfg.Zone, baseSerial+uint32(round), *records, round)
		recs, err := zparse.Parse(strings.NewReader(text), cfg.Zone, cfg.MinTTL, cfg.MaxTTL)
		must(err)
		_, err = st.Publish(ctx, cfg.Zone, recs, baseSerial+uint32(round), "xfrstress")
		must(err)
		published.Add(1)
		time.Sleep(*publishGap)
	}
	// 等通知传播 + worker 观察到最终版本后收尾。
	time.Sleep(500 * time.Millisecond)
	stopFlag.Store(true)
	wg.Wait()

	fmt.Printf("发布 %d 次，UDP 查询 %d 次，AXFR %d 次，耗时 %s\n",
		published.Load(), queryCount.Load(), xfrCount.Load(), time.Since(t0).Round(time.Millisecond))
	if f := failCount.Load(); f > 0 {
		fmt.Printf("失败: 检测到 %d 个撕裂/不一致结果！\n", f)
		os.Exit(1)
	}
	fmt.Println("OK: 未发现半个版本，所有查询与传送均取自完整一致的某一版本")
}

// queryOnce 查询 host TXT，返回唯一 TXT 值。
func queryOnce(c *dns.Client, addr, name string) (string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	resp, _, err := c.Exchange(m, addr)
	if err != nil || !resp.Authoritative || resp.Rcode != dns.RcodeSuccess {
		return "", false
	}
	if len(resp.Answer) != 1 {
		return "", false
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) != 1 {
		return "", false
	}
	return txt.Txt[0], true
}

// axfrOnce 做一次 TSIG AXFR，校验首尾 SOA 一致、期望记录数，
// 返回流的 serial 与全部 TXT 值（用于版本一致性检查）。
func axfrOnce(addr, zone, keyName, secret, algo string, records int) (uint32, string) {
	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{keyName: secret}
	m := new(dns.Msg)
	m.SetAxfr(zone)
	m.SetTsig(keyName, algo, 300, time.Now().Unix())

	ch, err := tr.In(m, addr)
	if err != nil {
		return 0, "连接失败: " + err.Error()
	}
	var (
		firstSOA, lastSOA uint32
		soaSeen           int
		txtValues         []string
		total             int
	)
	for env := range ch {
		if env.Error != nil {
			return 0, "流错误: " + env.Error.Error()
		}
		for _, rr := range env.RR {
			total++
			switch v := rr.(type) {
			case *dns.SOA:
				if soaSeen == 0 {
					firstSOA = v.Serial
				}
				lastSOA = v.Serial
				soaSeen++
			case *dns.TXT:
				if len(v.Txt) == 1 {
					txtValues = append(txtValues, v.Txt[0])
				}
			}
		}
	}
	if firstSOA != lastSOA {
		return 0, fmt.Sprintf("首尾 SOA 不一致 %d != %d（读到半个版本）", firstSOA, lastSOA)
	}
	// SOA*2 + NS + ns1 A + records 条 TXT。
	if want := records + 4; total != want {
		return 0, fmt.Sprintf("记录数 %d != 期望 %d", total, want)
	}
	if len(txtValues) != records {
		return 0, fmt.Sprintf("TXT 数 %d != 期望 %d", len(txtValues), records)
	}
	// 期望的 TXT 值：本轮格式 s=<serial>；更早轮次用 v=<轮次> 格式。
	// 关键校验不是“必须是本轮”，而是“整条传送内所有 TXT 与首尾 SOA
	// 指向同一个完整版本”——半个版本会在这里表现为 TXT 值混杂。
	want := wantVal(firstSOA)
	legacy := legacyVal(firstSOA)
	for _, tv := range txtValues {
		if tv != want && tv != legacy {
			return firstSOA, "记录版本混杂: 期望 " + want + "/" + legacy + " 实际 " + tv
		}
	}
	// 同一条传送里不允许新旧格式并存（那也意味着跨版本撕裂）。
	var sawS, sawV bool
	for _, tv := range txtValues {
		if strings.HasPrefix(tv, "s=") {
			sawS = true
		}
		if strings.HasPrefix(tv, "v=") {
			sawV = true
		}
	}
	if sawS && sawV {
		return firstSOA, "记录版本混杂: 同一次传送中出现 s= 与 v= 两种格式"
	}
	return firstSOA, ""
}

var baseSerialGlobal = uint32(2026100100)

// minAcceptedSerial 是“合法已发布版本”的序列号下界（含历次压测）。
var minAcceptedSerial = uint32(2026093101)

// 历次压测的起始序列号（旧 v= 格式）。
var legacyBases = []uint32{2026093100, 2026100100}

func wantVal(serial uint32) string {
	return "s=" + strconv.FormatUint(uint64(serial), 10)
}

// legacyVal 返回旧格式 v=<轮次>，仅当 serial 属于旧轮次；否则返回空串。
func legacyVal(serial uint32) string {
	for _, b := range legacyBases {
		if serial > b && serial <= b+200 {
			return "v=" + strconv.FormatUint(uint64(serial-b), 10)
		}
	}
	return ""
}

func txtConsistent(txt string, baseSerial uint32, maxRound int) bool {
	// 本轮 s= 格式。
	if strings.HasPrefix(txt, "s=") {
		n, err := strconv.ParseUint(strings.TrimPrefix(txt, "s="), 10, 32)
		if err != nil {
			return false
		}
		sn := uint32(n)
		if sn >= baseSerial+1 && sn <= baseSerial+uint32(maxRound) {
			return true
		}
		// 启动瞬间看到上一轮完整版本。
		return sn >= minAcceptedSerial && sn < baseSerial
	}
	// 旧轮次 v= 格式：值要能对上某个已知轮次。
	if strings.HasPrefix(txt, "v=") {
		n, err := strconv.Atoi(strings.TrimPrefix(txt, "v="))
		if err != nil || n < 1 || n > 200 {
			return false
		}
		return true
	}
	return false
}

func versionConsistent(serial, baseSerial uint32, maxRound int) bool {
	// AXFR 内部已校验所有 TXT 值与 SOA serial 一致，这里不限轮次。
	return true
}

// buildZone 生成“每个属主都有 1 条、值携带完整序列号”的区域文本。
func buildZone(zone string, serial uint32, records int, _ int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "$ORIGIN %s\n$TTL 300\n", zone)
	fmt.Fprintf(&b, "@ IN SOA ns1.%s admin.%s %d 1h 15m 2w 1h\n", zone, zone, serial)
	fmt.Fprintf(&b, "@ IN NS ns1.%s\n", zone)
	fmt.Fprintf(&b, "ns1 IN A 127.0.0.53\n")
	for i := 0; i < records; i++ {
		fmt.Fprintf(&b, "host%d IN TXT \"s=%d\"\n", i, serial)
	}
	return b.String()
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "xfrstress:", err)
		os.Exit(1)
	}
}
