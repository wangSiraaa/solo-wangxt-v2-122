package store

import (
	"github.com/miekg/dns"
)

const zmodelTypeSOA = dns.TypeSOA

func typeName(t uint16) string {
	if n, ok := dns.TypeToString[t]; ok {
		return n
	}
	return "TYPE" + itoa(int(t))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
