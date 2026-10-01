package config

import "testing"

func TestRejectNonLoopbackListen(t *testing.T) {
	c := validCfg()
	c.ListenUDP = "0.0.0.0:53" // 绑定全部接口必须拒绝
	if err := c.Validate(); err == nil {
		t.Fatal("监听 0.0.0.0 必须被拒绝")
	}
}

func TestRejectNonLoopbackACL(t *testing.T) {
	c := validCfg()
	c.TransferACL = []string{"10.0.0.0/8"}
	if err := c.Validate(); err == nil {
		t.Fatal("非回环 ACL 必须被拒绝")
	}
}

func TestRejectEmptyACL(t *testing.T) {
	c := validCfg()
	c.TransferACL = nil
	if err := c.Validate(); err == nil {
		t.Fatal("空 ACL 必须被拒绝（禁止向任意客户端传送）")
	}
}

func TestRejectBadTSIGAlgo(t *testing.T) {
	c := validCfg()
	c.TSIG["k.home.test."] = TSIGKey{Algorithm: "md5", SecretB64: "AA=="}
	if err := c.Validate(); err == nil {
		t.Fatal("不支持的 TSIG 算法必须被拒绝")
	}
}

func TestAcceptHmacVariants(t *testing.T) {
	for _, a := range []string{"hmac-sha256", "hmac-sha256.", "hmac-sha1", "hmac-sha512"} {
		c := validCfg()
		c.TSIG = map[string]TSIGKey{"k.home.test.": {Algorithm: a, SecretB64: "AA=="}}
		if err := c.Validate(); err != nil {
			t.Errorf("算法 %q 应被接受: %v", a, err)
		}
	}
}

func TestTTLBoundsConfig(t *testing.T) {
	c := validCfg()
	c.MinTTL, c.MaxTTL = 1000, 100
	if err := c.Validate(); err == nil {
		t.Fatal("min>max 必须报错")
	}
}

func validCfg() *Config {
	return &Config{
		ListenUDP:   "127.0.0.1:5553",
		ListenTCP:   "127.0.0.1:5553",
		Zone:        "home.test.",
		DBConn:      "postgres://x",
		MinTTL:      60,
		MaxTTL:      86400,
		NegTTL:      300,
		TransferACL: []string{"127.0.0.0/8"},
		TSIG: map[string]TSIGKey{
			"transfer.home.test.": {Algorithm: "hmac-sha256", SecretB64: "AA=="},
		},
	}
}
