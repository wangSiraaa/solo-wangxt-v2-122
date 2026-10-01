// zonectl 是区域管理命令行工具：初始化数据库、校验/发布区域文件、查看历史。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"dnssvc/internal/config"
	"dnssvc/internal/store"
	"dnssvc/internal/zmodel"
	"dnssvc/internal/zparse"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", envOr("ZONECTL_CFG", "configs/config.json"), "配置文件")
	_ = fs.Parse(os.Args[2:])
	args := fs.Args()

	cfg, err := config.Load(*cfgPath)
	must(err)

	ctx := context.Background()
	st, err := store.New(ctx, cfg.DBConn)
	must(err)
	defer st.Close()

	switch cmd {
	case "initdb":
		runInitDB(cfg.DBConn)
	case "validate":
		if len(args) < 1 {
			fatal("用法: zonectl validate <zonefile>")
		}
		recs := parseZoneFile(args[0], cfg.Zone, cfg.MinTTL, cfg.MaxTTL)
		soa := findSOA(recs)
		fmt.Printf("OK: %d 条记录，SOA serial=%d\n", len(recs), soa.Serial)
	case "publish":
		if len(args) < 1 {
			fatal("用法: zonectl publish <zonefile>（操作者取 $ZONE_AUTHOR）")
		}
		author := os.Getenv("ZONE_AUTHOR")
		runPublish(ctx, st, cfg, args[0], author)
	case "history":
		runHistory(ctx, st, cfg.Zone)
	case "changes":
		if len(args) < 1 {
			fatal("用法: zonectl changes <version>")
		}
		runChanges(ctx, st, cfg.Zone, parseInt(args[0]))
	case "current":
		runCurrent(ctx, st, cfg.Zone)
	default:
		usage()
		os.Exit(2)
	}
}

func parseZoneFile(path, zone string, minTTL, maxTTL uint32) []*zmodel.Record {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	recs, err := zparse.Parse(f, zone, minTTL, maxTTL)
	must(err)
	return recs
}

func findSOA(recs []*zmodel.Record) *dns.SOA {
	for _, r := range recs {
		if rr, ok := r.RR().(*dns.SOA); ok {
			return rr
		}
	}
	fatal("区域缺少 SOA")
	return nil
}

func runPublish(ctx context.Context, st *store.Store, cfg *config.Config, path, author string) {
	recs := parseZoneFile(path, cfg.Zone, cfg.MinTTL, cfg.MaxTTL)
	serial := findSOA(recs).Serial
	p, err := st.Publish(ctx, cfg.Zone, recs, serial, author)
	must(err)
	verb := "发布"
	if p.FirstTime {
		verb = "首次发布"
	}
	fmt.Printf("%s成功: version=%d serial=%d，变更 %d 条\n", verb, p.Version, p.Serial, len(p.Changes))
	for _, c := range p.Changes {
		fmt.Printf("  %s %-5s %s\n", c.Change, c.RType, c.RRText)
	}
}

func runHistory(ctx context.Context, st *store.Store, zone string) {
	hs, err := st.History(ctx, zone)
	must(err)
	if len(hs) == 0 {
		fmt.Println("(无版本)")
		return
	}
	fmt.Printf("%-8s %-12s %-21s %-10s %s\n", "VERSION", "SERIAL", "PUBLISHED_AT", "BY", "CHANGES")
	for _, h := range hs {
		fmt.Printf("%-8d %-12d %-21s %-10s %d\n", h.Version, h.Serial, h.PublishedAt, h.By, h.Changes)
	}
}

func runChanges(ctx context.Context, st *store.Store, zone string, version int64) {
	cs, err := st.ChangesOf(ctx, zone, version)
	must(err)
	for _, c := range cs {
		fmt.Printf("%s %-5s %s\n", c.Change, c.RType, c.RRText)
	}
}

func runCurrent(ctx context.Context, st *store.Store, zone string) {
	v, err := st.Current(ctx, zone)
	must(err)
	if v == nil {
		fmt.Println("(无已发布版本)")
		return
	}
	fmt.Printf("version=%d serial=%d records=%d\n", v.Version, v.Serial, len(v.Records))
}

func runInitDB(conn string) {
	// 用 store 的连接初始化 schema（简单实现：读取 sql 文件执行）。
	ctx := context.Background()
	st, err := store.New(ctx, conn)
	must(err)
	defer st.Close()
	if err := st.Migrate(ctx, "sql/schema.sql"); err != nil {
		// 尝试相对二进制/仓库根的路径
		err = st.Migrate(ctx, "/workspace/dnssvc/sql/schema.sql")
	}
	must(err)
	fmt.Println("schema 已初始化")
}

func parseInt(s string) int64 {
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	must(err)
	return v
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法: zonectl [-config config.json] <命令> [参数]
命令:
  initdb                      初始化数据库表
  validate <zonefile>         只校验，不发布
  publish  <zonefile>         原子发布新版本（serial 必须递增）
  current                     查看当前版本
  history                     列出版本历史
  changes  <version>          查看某次发布的变更日志`)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func must(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "zonectl: "+format+"\n", a...)
	os.Exit(1)
}
