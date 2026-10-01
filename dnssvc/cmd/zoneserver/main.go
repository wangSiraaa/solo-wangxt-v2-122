// zoneserver 是权威 DNS 服务进程。只绑定回环地址，只服务配置中的单一区域。
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"dnssvc/internal/config"
	"dnssvc/internal/store"
	"dnssvc/internal/zserve"
)

func main() {
	cfgPath := flag.String("config", envOr("ZONECTL_CFG", "configs/config.json"), "配置文件路径")
	_ = flag.CommandLine
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.New(ctx, cfg.DBConn)
	if err != nil {
		log.Fatalf("PostgreSQL 不可用: %v", err)
	}
	defer st.Close()

	srv, err := zserve.New(cfg, st)
	if err != nil {
		log.Fatalf("初始化服务: %v", err)
	}

	go srv.RunRefreshLoop(ctx)

	go func() {
		log.Printf("zoneserver: 在 udp/tcp %s 服务区域 %s", cfg.ListenUDP, cfg.Zone)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("监听失败: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("zoneserver: 退出中")
	cancel()
	srv.Shutdown()
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
