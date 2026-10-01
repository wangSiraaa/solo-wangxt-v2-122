package zserve

import (
	"net"
	"net/netip"

	"dnssvc/internal/config"
)

// ACL 判断客户端是否在授权的回环网段内。
type ACL struct {
	prefixes []netip.Prefix
}

// NewACL 解析配置中的 CIDR（config.Validate 已保证它们都在回环网段）。
func NewACL(cfg *config.Config) (*ACL, error) {
	a := &ACL{}
	for _, s := range cfg.TransferACL {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		a.prefixes = append(a.prefixes, p.Masked())
	}
	return a, nil
}

// Allow 报告客户端 IP 是否被授权。
func (a *ACL) Allow(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, p := range a.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
