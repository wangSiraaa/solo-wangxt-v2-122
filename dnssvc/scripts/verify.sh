#!/usr/bin/env bash
# 最终验收：全部用标准 dig 核对。任何一步不符合预期即退出非零。
set -u
source "$(dirname "$0")/env.sh"
S="@127.0.0.1 -p 5553"
K="-k $SVCROOT/configs/tsig.key"
PASS=0; FAIL=0

check() { # desc expected actual
  if [ "$2" == "$3" ]; then echo "PASS: $1 (= $3)"; PASS=$((PASS+1));
  else echo "FAIL: $1 期望[$2] 实际[$3]"; FAIL=$((FAIL+1)); fi
}

rcode() { "$DIG" $S "$1" "$2" ${3:-} +noall +comments 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1; }

echo "== 1) 明确支持的记录类型与同名多记录 =="
check "www A 条数" 2 "$($DIG $S www.home.test A +short | wc -l | tr -d ' ')"
check "www A 含 127.0.0.10" "1" "$($DIG $S www.home.test A +short | grep -c '^127.0.0.10$' | tr -d ' ')"
check "MX 条数" 2 "$($DIG $S home.test MX +short | wc -l | tr -d ' ')"
check "TXT 条数" 2 "$($DIG $S txt.home.test TXT +short | wc -l | tr -d ' ')"
check "SRV" "10 60 5060 sip.home.test." "$($DIG $S _sip._tcp.home.test SRV +short)"
check "CAA" "0 issue \"ca.example\"" "$($DIG $S home.test CAA +short)"
check "PTR 类支持(查无记录 NODATA)" "NOERROR" "$(rcode ns1.home.test PTR)"
check "不支持类型 RRSIG" "NOTIMP" "$(rcode www.home.test RRSIG)"

echo "== 2) CNAME/DNAME 链 =="
check "CNAME 链首条" "alias.home.test.	3600	IN	CNAME	www.home.test." "$($DIG $S alias.home.test A +noall +answer | head -1)"
check "DNAME 合成 CNAME 目标" "foo.new.home.test." "$($DIG $S foo.old.home.test A +noall +answer | awk '$4=="CNAME"{print $5}')"
check "域外 CNAME 只回 CNAME" 1 "$($DIG $S ext.home.test A +noall +answer | wc -l | tr -d ' ')"
check "域外 CNAME 状态" "NOERROR" "$(rcode ext.home.test A)"

echo "== 3) 负响应与权威信息 =="
check "NXDOMAIN 状态" "NXDOMAIN" "$(rcode nope.home.test A)"
check "NXDOMAIN 权威 SOA 条数" 1 "$($DIG $S nope.home.test A +noall +authority | grep -c SOA | tr -d ' ')"
check "NODATA 状态" "NOERROR" "$(rcode mail.home.test AAAA)"
check "NODATA 权威 SOA 条数" 1 "$($DIG $S mail.home.test AAAA +noall +authority | grep -c SOA | tr -d ' ')"
check "负响应 SOA TTL=negTTL(300)" 300 "$($DIG $S nope.home.test A +noall +authority | awk '$4=="SOA"{print $2}')"
check "AA 权威位" "1" "$($DIG $S www.home.test A +noall +comments | grep -c 'flags: qr aa' | tr -d ' ')"

echo "== 4) 不提供递归/域外拒绝 =="
check "域外查询" "REFUSED" "$(rcode www.google.com A)"
check "无 RA 位" 0 "$($DIG $S www.home.test A +noall +comments | grep -c 'flags:.*ra' | tr -d ' ')"

echo "== 5) AXFR 门禁与 TSIG =="
# dig 对 AXFR 强制走 TCP；UDP AXFR 的 FORMERR 由 Go 单测覆盖。
check "TCP AXFR 无TSIG" "REFUSED" "$($DIG $S home.test AXFR +tcp +noall +comments 2>/dev/null | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
AXFR_OUT=$($DIG $S $K home.test AXFR +tcp +nomultiline 2>/dev/null)
check "AXFR SOA 条数(首尾)" 2 "$(echo "$AXFR_OUT" | grep -c '	IN	SOA	')"
check "AXFR 记录总数(含首尾SOA与TSIG)" 22 "$(echo "$AXFR_OUT" | sed -n 's/.*XFR size: \([0-9]*\) records.*/\1/p')"
check "AXFR 末带 TSIG 且无验签错误" 0 "$(echo "$AXFR_OUT" | grep -ci 'couldn.t verify\|BADTIME\|BADSIG\|Transfer failed')"

echo "== 6) IXFR =="
IXFR_UP=$($DIG $S $K home.test IXFR=2026100800 +tcp +short +nomultiline 2>/dev/null)
check "IXFR 已最新仅 1 SOA" 1 "$(printf '%s\n' "$IXFR_UP" | grep -c 'admin.home.test')"

echo
echo "结果: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
