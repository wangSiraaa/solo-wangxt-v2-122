# dnssvc — 本地测试域权威 DNS 区域服务

仅供**本地测试域**使用的权威 DNS 服务：

- Go + [`miekg/dns`](https://github.com/miekg/dns) 解析记录与请求；
- PostgreSQL 保存**区域版本**与**变更日志**；
- 不做页面，不提供公开递归解析，绝不向任意外部地址抓取内容；
- 区域更新**单事务原子发布**，查询与传送不可能看到半个版本；
- 支持明确列出的记录类型、AXFR 与 IXFR；
- CNAME 冲突、域外记录一律拒绝；
- 负响应（NXDOMAIN/NODATA）带正确的权威 SOA；
- 传送限定授权（回环）客户端，并使用库内置的 **TSIG**（不自创签名协议）。

## 目录结构

```
cmd/zoneserver   服务进程（UDP+TCP，仅回环）
cmd/zonectl      管理 CLI：initdb/validate/publish/current/history/changes
cmd/xfrstress    “更新中传送 + 原子发布”压测/撕裂检测工具
cmd/junkclient   畸形/越权/诱导递归请求的健壮性测试客户端
internal/config  配置与安全约束（强制回环监听/回环 ACL/合法 TSIG）
internal/zmodel  记录模型、校验规则、不可变快照（原子发布核心）
internal/zparse  RFC1035 区域文件解析（拒绝 $INCLUDE/$GENERATE）
internal/store   PostgreSQL：版本、变更日志、NOTIFY 监听、事务发布
internal/zserve  DNS 服务：查询、负响应、AXFR/IXFR、TSIG MAC 链
sql/schema.sql   数据库结构
configs/         配置、TSIG 密钥、各测试区域文件
scripts/         环境脚本与 dig 验收脚本
```

## 运行（本机免 root 工具链）

工具链（Go、PostgreSQL、dig）均安装在仓库下，见 `scripts/env.sh`：

```bash
source scripts/env.sh

# 1) 启动 PostgreSQL（仅 127.0.0.1:55432，socket 在 /tmp/pgrun）
#    （首次需 initdb，已在交付环境完成）

# 2) 初始化库表
zonectl initdb

# 3) 校验 / 发布区域
zonectl validate configs/zones/home.test.final.zone
ZONE_AUTHOR=infra zonectl publish configs/zones/home.test.final.zone
zonectl history
zonectl changes <version>

# 4) 启动服务（127.0.0.1:5553）
zoneserver
```

## 支持的记录类型（明确清单）

`SOA NS A AAAA CNAME DNAME MX TXT SRV CAA PTR`。

- 区域必须恰好 1 条 SOA、顶点至少 1 条 NS；
- 同名同类型允许**多条**（多值 RRset，如多个 A/MX/TXT）；完全重复记录拒绝；
- 清单之外的类型：载入拒绝，查询返回 `NOTIMP`。

## 校验与拒绝规则（发布前全部生效）

- **CNAME 冲突**：CNAME 与任何其他类型同名拒绝；区域顶点 CNAME 拒绝；自循环拒绝。
- **域外记录**：属主不在区域内拒绝；`$ORIGIN` 不得改写到区域外；顶点 NS 目标须在区内。
- **TTL 边界**：每条记录 TTL 必须落在 `[min_ttl, max_ttl]`（默认 60..86400，闭区间，边界值通过）。
- **文件安全**：拒绝 `$INCLUDE`、`$GENERATE`（注释/字符串内的伪指令不误判），
  防止服务端被输入诱导读取本地文件或发起外部访问。

## 原子发布（查询看不到半个版本）

- 发布在**单个 PostgreSQL 事务**内：锁区域行 → 校验 serial 严格递增 →
  写版本 JSONB → 写变更日志 → `pg_notify`，提交后才投递通知。
- 服务端用 `atomic.Pointer[Snapshot]` 持有**不可变快照**；发布 = 构建完整新快照后整体替换指针。
- AXFR/IXFR 从入口处取一次快照，整条流来自同一版本，首尾 SOA 必然一致。

## 负响应（权威信息正确）

- `NXDOMAIN`：Authority 放 SOA（RFC 2308 #name TTL = min(SOA TTL, neg_ttl)）；
- `NODATA`（名字存在、类型不存在）：NOERROR + Authority SOA（#no data TTL）；
- CNAME/DNAME 重写后末端名字不存在：返回链 + NXDOMAIN（RFC 6672）；
- CNAME 指向区域外：权威边界处停止，只回 CNAME，**绝不继续解析外部目标**。

## 传送（AXFR/IXFR）

- 仅 **TCP**（UDP AXFR/IXFR → FORMERR）；
- 客户端源地址必须落在授权的**回环**网段（`transfer_acl`，配置层强制回环）；
- 必须携带 **TSIG**，密码学校验由 miekg/dns 完成；
- 多消息传送按 RFC 2845 对每条消息附 TSIG（首条完整校验、后续 timers-only），MAC 链由库维护；
- IXFR（RFC 1995）：已最新→单 SOA；可在历史版本定位→逐版本 del/add 块并以当前 SOA 收尾；
  基础版本不可得→标准回退 AXFR。

## 测试

### 标准 dig 验收

```bash
./scripts/verify.sh        # 25 项，全部用 dig 核对响应与传送
```

### 单元测试（含竞态检测）

```bash
go test -race ./...
```

### TTL 边界 / 同名多记录 / 更新中传送

- TTL 边界、同名多记录、CNAME 冲突、域外记录：`go test ./...` 与 `zonectl validate configs/zones/bad-*.zone`；
- 更新中传送（核心并发测试）：

```bash
# 高频全量改写，同时大量并发 UDP 查询 + TSIG AXFR；
# 校验首尾 SOA 一致、整次传送记录同属一个版本：
xfrstress -base-serial <新号段> -rounds 80 -records 1500 \
          -query-workers 10 -xfr-workers 6 -gap 2ms
# 期望：“未发现半个版本 …”。
```

为证明该测试确实能抓问题，提供故障注入构建（仅测试用）：

```bash
go build -tags faultinject -o bin/zoneserver-fault ./cmd/zoneserver
FAULT_TORN_XFR=1 ./bin/zoneserver-fault   # 让 AXFR 跨块重读快照
xfrstress ...                             # 会报告“首尾 SOA 不一致（读到半个版本）”
```

### 错误请求不导致外抓

```bash
junkclient    # 畸形包/错误 opcode/坏 TSIG/UDP 传送/诱导递归：
              # 服务 REFUSED/FORMERR/NOTIMP，且不崩溃、不挂起、不发起外部连接
```

监听与连接经核对仅在 `127.0.0.1:5553`（PostgreSQL 走 `/tmp` Unix socket）；
服务端代码中不存在任何出站 DNS 客户端、转发器或上游配置。

## 配置（configs/config.json）

| 字段 | 含义 |
| --- | --- |
| listen_udp / listen_tcp | 必须是回环地址 |
| zone | 单一被服务区域 FQDN |
| db_conn | PostgreSQL 连接串（本机） |
| min_ttl / max_ttl | 记录 TTL 闭区间边界（秒） |
| neg_ttl | 负响应 SOA TTL 上限 |
| transfer_acl | 允许传送的 CIDR，必须整体位于回环网段 |
| tsig | 密钥名 → {algorithm, secret(base64)}，hmac-sha1/256/512 |

TSIG 密钥为 `configs/tsig.key`（dig `-k` 格式），权限 600。
