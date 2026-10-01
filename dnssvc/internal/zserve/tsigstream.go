package zserve

import (
	"time"

	"github.com/miekg/dns"
)

// streamSigner 跟踪一次 TSIG 传送流的签名状态（RFC 2845 4.4）。
//
// 多消息传送中，每条 DNS 消息都必须携带 TSIG RR：第一条做完整
// HMAC 校验，其后每条使用“仅时间戳”模式（timers-only），MAC 链由
// miekg/dns 的 ResponseWriter 内部自动维护（首条输入 MAC 为请求
// MAC，之后为上一条响应的 MAC）。不使用任何自创签名协议。
type streamSigner struct {
	t       *dns.TSIG
	w       dns.ResponseWriter
	started bool
}

// write 写出流中的一条消息并在需要时附加 TSIG。
func (sg *streamSigner) write(m *dns.Msg) error {
	if sg.t != nil {
		m.SetTsig(dns.CanonicalName(sg.t.Hdr.Name), sg.t.Algorithm, sg.t.Fudge, time.Now().Unix())
		if err := sg.w.WriteMsg(m); err != nil {
			return err
		}
		// 首条之后：切换为 timers-only，库继续沿用上一条 MAC。
		if !sg.started {
			sg.started = true
			sg.w.TsigTimersOnly(true)
		}
		return nil
	}
	return sg.w.WriteMsg(m)
}
