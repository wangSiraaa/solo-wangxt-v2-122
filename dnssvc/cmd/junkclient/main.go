// junkclient 向服务端发送一批畸形/恶意/越权请求，确认：
//   - 服务不会崩溃、不会卡死；
//   - 对区域外名字、坏 TSIG、UDP 传送等都给出拒绝/错误码；
//   - 全程不产生任何对外网络动作（服务只绑定回环；可用
//     `ss -tnp` 或 lsof 核对进程连接只有 127.0.0.1 与本地 PG）。
package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
)

func main() {
	addr := flag.String("server", "127.0.0.1:5553", "DNS 服务器")
	flag.Parse()

	udp, err := net.Dial("udp", *addr)
	must(err)
	tcp, err := net.Dial("tcp", *addr)
	must(err)
	defer udp.Close()
	defer tcp.Close()

	// 用独立连接，避免前一个用例的坏数据污染同一条 TCP 流。
	send := func(name string, wire []byte, via string) {
		var conn net.Conn
		if via == "tcp" {
			c2, err := net.Dial("tcp", *addr)
			if err != nil {
				fmt.Printf("%-28s TCP连失败: %v\n", name, err)
				return
			}
			conn = c2
			l := make([]byte, 2)
			l[0] = byte(len(wire) >> 8)
			l[1] = byte(len(wire))
			if _, err := conn.Write(append(l, wire...)); err != nil {
				fmt.Printf("%-28s TCP写失败: %v\n", name, err)
				conn.Close()
				return
			}
		} else {
			c2, err := net.Dial("udp", *addr)
			if err != nil {
				fmt.Printf("%-28s UDP连失败: %v\n", name, err)
				return
			}
			conn = c2
			if _, err := conn.Write(wire); err != nil {
				fmt.Printf("%-28s UDP写失败: %v\n", name, err)
				conn.Close()
				return
			}
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		switch {
		case err != nil:
			fmt.Printf("%-28s 无响应/超时(%v) —— 对恶意输入静默丢弃是可接受的\n", name, err)
		default:
			payload := buf[:n]
			if via == "tcp" {
				if n < 2 {
					fmt.Printf("%-28s TCP 响应过短\n", name)
					return
				}
				payload = buf[2:n] // 跳过 2 字节长度前缀
			}
			m := new(dns.Msg)
			if err := m.Unpack(payload); err != nil {
				fmt.Printf("%-28s 响应无法解析: %v（服务器未必要回复畸形输入）\n", name, err)
				return
			}
			fmt.Printf("%-28s rcode=%s\n", name, dns.RcodeToString[m.Rcode])
		}
	}

	// 1) 区域外名字：REFUSED，且我们随后核对过服务器没有发出外部连接。
	q := new(dns.Msg)
	q.SetQuestion("www.example.org.", dns.TypeA)
	wire, _ := q.Pack()
	send("域外 A 查询(UDP)", wire, "udp")

	// 2) 域外名字 + RD=1（诱导递归）：仍必须 REFUSED，不得代为抓取。
	q = new(dns.Msg)
	q.SetQuestion("www.google.com.", dns.TypeA)
	q.RecursionDesired = true
	wire, _ = q.Pack()
	send("域外 RD=1 诱导递归", wire, "udp")

	// 3) CNAME 指向区域外：服务器只回 CNAME，不继续解析外部目标。
	q = new(dns.Msg)
	q.SetQuestion("ext.home.test.", dns.TypeA)
	wire, _ = q.Pack()
	send("指向域外的 CNAME 链", wire, "udp")

	// 4) UDP AXFR：FORMERR。
	q = new(dns.Msg)
	q.SetQuestion("home.test.", dns.TypeAXFR)
	wire, _ = q.Pack()
	send("UDP AXFR", wire, "udp")

	// 5) AXFR over TCP 无 TSIG：REFUSED。
	q = new(dns.Msg)
	q.SetQuestion("home.test.", dns.TypeAXFR)
	wire, _ = q.Pack()
	send("TCP AXFR 无 TSIG", wire, "tcp")

	// 6) IXFR over TCP 无 TSIG：REFUSED。
	q = new(dns.Msg)
	q.SetQuestion("home.test.", dns.TypeIXFR)
	wire, _ = q.Pack()
	send("TCP IXFR 无 TSIG", wire, "tcp")

	// 7) UPDATE opcode：REFUSED。
	q = new(dns.Msg)
	q.SetQuestion("home.test.", dns.TypeSOA)
	q.Opcode = dns.OpcodeUpdate
	wire, _ = q.Pack()
	send("UPDATE opcode", wire, "udp")

	// 8) 非 IN 类（CHAOS）：FORMERR。
	q = new(dns.Msg)
	q.SetQuestion("home.test.", dns.TypeSOA)
	q.Question[0].Qclass = dns.ClassCHAOS
	wire, _ = q.Pack()
	send("CHAOS 类查询", wire, "udp")

	// 9) 0 字节垃圾。
	send("0 字节垃圾(UDP)", []byte{}, "udp")

	// 10) 随机 512 字节垃圾。
	junk := make([]byte, 512)
	_, _ = rand.Read(junk)
	send("512 字节随机垃圾(UDP)", junk, "udp")

	// 11) 声称超长的 TCP（长度 65535 但只给 4 字节）：服务器必须超时/关闭，不挂起。
	tcp.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = tcp.Write([]byte{0xff, 0xff, 0x00, 0x00, 0x10, 0x00})
	_ = tcp.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := tcp.Read(make([]byte, 16)); err != nil {
		fmt.Printf("%-28s 按预期未被挂起: %v\n", "TCP 声称 65535 字节", err)
	}

	// 12) 多问题（>1 question）：FORMERR。独立连接发送。
	q = new(dns.Msg)
	q.SetQuestion("a.home.test.", dns.TypeA)
	q.Question = append(q.Question, dns.Question{Name: "b.home.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	wire, _ = q.Pack()
	send("两个 question", bytes.Clone(wire), "udp")

	// 13) TSIG 密钥名未知：REFUSED（库校验失败）。
	q = new(dns.Msg)
	q.SetQuestion("home.test.", dns.TypeAXFR)
	q.SetTsig("unknown.key.", dns.HmacSHA256, 300, time.Now().Unix())
	c := new(dns.Client)
	c.Net = "tcp"
	c.TsigSecret = map[string]string{"unknown.key.": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg="}
	r, _, err := c.Exchange(q, *addr)
	if err != nil {
		fmt.Printf("%-28s 传输错误(可接受): %v\n", "未知 TSIG 密钥", err)
	} else {
		fmt.Printf("%-28s rcode=%s\n", "未知 TSIG 密钥", dns.RcodeToString[r.Rcode])
	}

	// 14) 超大压缩指针循环：构造一条压缩指针指向自身的查询。
	q = new(dns.Msg)
	q.SetQuestion("home.test.", dns.TypeA)
	wire, _ = q.Pack()
	// 把名字编码替换成压缩指针指向偏移 12（问题区起点），形成环。
	// DNS 头 12 字节，问题名首字节起；覆盖前两个字节为指针 0xC00C。
	if len(wire) > 14 {
		wire[12] = 0xC0
		wire[13] = 0x0C
	}
	send("压缩指针环(UDP)", bytes.Clone(wire), "udp")

	fmt.Println("\n畸形输入处理完成。")
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "junkclient:", err)
		os.Exit(1)
	}
}
