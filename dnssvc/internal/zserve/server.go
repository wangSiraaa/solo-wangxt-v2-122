// Package zserve 是权威区域 DNS 服务：只服务单一本地测试区域，
// 不配置任何上游/转发器，绝不对外发起递归查询。
package zserve

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"

	"dnssvc/internal/config"
	"dnssvc/internal/store"
	"dnssvc/internal/zmodel"
)

// Server 持有 UDP/TCP 两个 dns.Server，共享同一个无状态 Handler，
// 通过原子快照读取当前版本。
type Server struct {
	cfg    *config.Config
	store  *store.Store
	holder *holder
	acl    *ACL
	secret map[string]string // TSIG 密钥名 -> base64（交给 miekg/dns 校验）

	udp *dns.Server
	tcp *dns.Server
}

// New 创建服务实例并加载当前版本。
func New(cfg *config.Config, st *store.Store) (*Server, error) {
	acl, err := NewACL(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		store:  st,
		holder: &holder{},
		acl:    acl,
		secret: map[string]string{},
	}
	for name, k := range cfg.TSIG {
		s.secret[strings.ToLower(dns.CanonicalName(name))] = k.SecretB64
	}
	if err := s.Refresh(context.Background()); err != nil {
		return nil, fmt.Errorf("加载初始版本: %w", err)
	}
	return s, nil
}

// Snapshot 返回当前快照（可能为 nil：区域尚无版本）。
func (s *Server) Snapshot() *zmodel.Snapshot { return s.holder.load() }

// Refresh 从数据库读取最新版本并整体替换快照。
func (s *Server) Refresh(ctx context.Context) error {
	v, err := s.store.Current(ctx, s.cfg.Zone)
	if err != nil {
		return err
	}
	if v == nil {
		log.Printf("zserve: 区域 %s 尚无已发布版本", s.cfg.Zone)
		return nil
	}
	if err := zmodel.ValidateSet(s.cfg.Zone, s.cfg.MinTTL, s.cfg.MaxTTL, v.Records); err != nil {
		return fmt.Errorf("数据库中的版本未通过校验: %w", err)
	}
	snap := zmodel.Build(s.cfg.Zone, v.Records)
	s.holder.store(snap) // 唯一的发布点：原子替换
	log.Printf("zserve: 已加载版本 %d serial=%d，%d 条记录",
		v.Version, v.Serial, len(v.Records))
	return nil
}

// RunRefreshLoop 监听数据库 NOTIFY，收到即重载。
func (s *Server) RunRefreshLoop(ctx context.Context) {
	l := s.store.NewListener(s.cfg.Zone)
	go l.Run(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.Events():
			if err := s.Refresh(ctx); err != nil {
				log.Printf("zserve: 重载失败: %v", err)
			}
		}
	}
}

// ListenAndServe 启动 UDP 与 TCP 监听。
func (s *Server) ListenAndServe() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNS)

	s.udp = &dns.Server{
		Addr:       s.cfg.ListenUDP,
		Net:        "udp",
		Handler:    mux,
		TsigSecret: s.secret,
	}
	s.tcp = &dns.Server{
		Addr:       s.cfg.ListenTCP,
		Net:        "tcp",
		Handler:    mux,
		TsigSecret: s.secret,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()

	// 任一监听失败即返回。
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			s.Shutdown()
			return err
		}
	}
	return nil
}

// Shutdown 停止两个监听器。
func (s *Server) Shutdown() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}
