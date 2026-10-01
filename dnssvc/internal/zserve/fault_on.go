//go:build faultinject

package zserve

import (
	"os"
	"strconv"

	"github.com/miekg/dns"

	"dnssvc/internal/zmodel"
)

// 故障注入构建（-tags faultinject）：当设置 FAULT_TORN_XFR 时，
// AXFR 每个消息块都重新读取当前快照，且块大小被调小，
// 以制造“更新中跨版本撕裂”的传送，仅用于验证测试本身有效。
func init() { faultEnabled = os.Getenv("FAULT_TORN_XFR") != "" }

var faultEnabled bool

func (s *Server) axfrSnapshot(snap *zmodel.Snapshot) *zmodel.Snapshot {
	if faultEnabled {
		if cur := s.holder.load(); cur != nil {
			return cur
		}
	}
	return snap
}

func chunkLimit(dflt int) int {
	if faultEnabled {
		if v := os.Getenv("FAULT_CHUNK"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 100 {
				return n
			}
		}
		return 4000
	}
	return dflt
}

var _ = dns.TypeA
