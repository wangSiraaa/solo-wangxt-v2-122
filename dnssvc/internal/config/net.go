package config

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// isLoopbackAddr 校验 host:port 形式的监听地址，host 必须是回环地址。
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// 允许只有端口的 ":5354" 吗？不允许——那会绑定全部接口。
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// 拒绝主机名（如 localhost 以外的名字）；localhost 也拒绝，
		// 强制写明 127.0.0.1，避免解析到非回环地址。
		return false
	}
	return ip.IsLoopback()
}

// validateLoopbackCIDR 校验传送 ACL：必须是 CIDR，且整体落在回环网段内。
func validateLoopbackCIDR(s string) error {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("ACL 条目 %q 不是合法 CIDR: %w", s, err)
	}
	if !p.Addr().IsLoopback() {
		return fmt.Errorf("ACL 条目 %q 不是回环网段：传送只授权本机客户端", s)
	}
	// 127.0.0.0/8 与 ::1/128 以外的前缀，即使地址碰巧是回环也要收紧。
	loop4 := netip.MustParsePrefix("127.0.0.0/8")
	loop6 := netip.MustParsePrefix("::1/128")
	if p.Addr().Is4() && !p.Overlaps(loop4) {
		return fmt.Errorf("ACL 条目 %q 越出回环网段", s)
	}
	if p.Addr().Is6() && !p.Overlaps(loop6) {
		return fmt.Errorf("ACL 条目 %q 越出回环网段", s)
	}
	return nil
}
