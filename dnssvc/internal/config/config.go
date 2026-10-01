// Package config 定义区域服务的本地配置。
//
// 该服务只在本地测试域运行：监听地址固定为 loopback，只服务单一区域，
// 不配置任何上游解析器，因此永远不会向外部地址发起解析请求。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// Config 是服务端与 CLI 共用的配置。
type Config struct {
	// ListenUDP/ListenTCP 为 DNS 监听地址，必须是本机回环地址。
	ListenUDP string `json:"listen_udp"`
	ListenTCP string `json:"listen_tcp"`

	// Zone 是被服务区域的 FQDN（大小写不敏感，内部转小写）。
	Zone string `json:"zone"`

	// DBConn 是 PostgreSQL 连接串（同样只连本机）。
	DBConn string `json:"db_conn"`

	// MinTTL/MaxTTL 是区域记录允许的 TTL 闭区间边界（秒）。
	MinTTL uint32 `json:"min_ttl"`
	MaxTTL uint32 `json:"max_ttl"`
	// NegTTL 是负响应 SOA 权威段的 TTL（取 min(SOA TTL, NegTTL)）。
	NegTTL uint32 `json:"neg_ttl"`

	// TransferACL 允许发起 AXFR/IXFR 的客户端地址（CIDR）。
	// 传送仅允许这些来源，并且仍须通过 TSIG 校验。
	TransferACL []string `json:"transfer_acl"`

	// TSIG 密钥表：密钥名 -> base64 密钥。服务端使用 miekg/dns
	// 内置 TSIG 校验，不自创任何签名协议。
	TSIG map[string]TSIGKey `json:"tsig"`
}

// TSIGKey 描述一把库支持的 TSIG 密钥。
type TSIGKey struct {
	Algorithm string `json:"algorithm"` // hmac-sha256 / hmac-sha1 / hmac-sha512
	SecretB64 string `json:"secret"`    // base64 编码的原始密钥
}

// Load 从 path 读取并校验配置。
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("解析配置: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate 做边界与安全约束校验。
func (c *Config) Validate() error {
	if c.ListenUDP == "" || c.ListenTCP == "" {
		return fmt.Errorf("listen_udp/listen_tcp 不能为空")
	}
	if !isLoopbackAddr(c.ListenUDP) || !isLoopbackAddr(c.ListenTCP) {
		return fmt.Errorf("只允许监听回环地址，拒绝绑定: %q/%q", c.ListenUDP, c.ListenTCP)
	}
	z := dns.CanonicalName(c.Zone)
	if z == "." || z == "" {
		return fmt.Errorf("zone 非法: %q", c.Zone)
	}
	c.Zone = z
	if c.MinTTL == 0 || c.MaxTTL < c.MinTTL {
		return fmt.Errorf("TTL 边界非法: min=%d max=%d", c.MinTTL, c.MaxTTL)
	}
	if c.NegTTL == 0 {
		return fmt.Errorf("neg_ttl 必须大于 0")
	}
	if len(c.TransferACL) == 0 {
		return fmt.Errorf("transfer_acl 不能为空：不允许向任意客户端传送")
	}
	for _, n := range c.TransferACL {
		if err := validateLoopbackCIDR(n); err != nil {
			return err
		}
	}
	if len(c.TSIG) == 0 {
		return fmt.Errorf("tsig 不能为空：传送必须使用 TSIG")
	}
	for name, k := range c.TSIG {
		if dns.CanonicalName(name) == "" {
			return fmt.Errorf("TSIG 密钥名非法: %q", name)
		}
		// 兼容 dig 密钥文件写法（hmac-sha256 无尾点）与库常量（带尾点）。
		k.Algorithm = strings.ToLower(strings.TrimSpace(k.Algorithm))
		if !strings.HasSuffix(k.Algorithm, ".") {
			k.Algorithm += "."
		}
		switch k.Algorithm {
		case dns.HmacSHA1, dns.HmacSHA256, dns.HmacSHA512:
		default:
			return fmt.Errorf("TSIG 算法 %q 不被库支持/不允许", k.Algorithm)
		}
		c.TSIG[name] = k
		if k.SecretB64 == "" {
			return fmt.Errorf("TSIG 密钥 %s 的 secret 为空", name)
		}
	}
	if c.DBConn == "" {
		return fmt.Errorf("db_conn 为空")
	}
	return nil
}
