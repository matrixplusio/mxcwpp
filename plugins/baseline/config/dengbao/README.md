# 等保 2.0 / CIS RHEL L1 基线 (MVP-2b)

| 文件 | 规则集 | OS | 规则数 |
|---|---|---|---|
| `dengbao/dengbao-l3-rhel.json` | GB/T 22239-2019 等保 2.0 三级 | RHEL/CentOS/Rocky/AlmaLinux/Oracle | 40 |
| `cis-rhel/cis-rhel8-l1.json` | CIS RHEL 8 Benchmark v2.0.0 Level 1 Server | RHEL 8/CentOS Stream 8/Rocky 8/Alma 8 | 40 |
| `cis/centos.json` | CIS Benchmark (自研) | CentOS/Rocky/AlmaLinux | 16 |
| `cis/debian.json` | CIS Benchmark (自研) | Debian | 17 |
| `cis/ubuntu.json` | CIS Benchmark (自研) | Ubuntu | 17 |
| **合计** | | | **130** |

距 ref/00 目标 200 条还差 70 条。后续 PR 补:
- Windows Server 基线 (M1-P1-1)
- Ubuntu 22.04 等保 (扩 DB_L3_*)
- 中间件 (Redis/Postgres/RabbitMQ/Kafka, 见 plugins/baseline/config/middleware/)
- K8s CIS-Bench-K8s-v1.27 (120 条)

## 等保 2.0 三级覆盖维度

```
8.1.4.1 身份鉴别       — 6 条 (口令策略 / 空口令 / 失败处理)
8.1.4.2 访问控制       — 9 条 (sudo / umask / 关键文件 / UID 唯一)
8.1.4.3 安全审计       — 7 条 (auditd / rsyslog / 日志保留)
8.1.4.4 入侵防范       — 12 条 (服务最小化 / SSH / 网络参数 / 防火墙 / SELinux)
8.1.4.5 恶意代码防范   — 2 条 (ClamAV / 病毒库)
8.1.4.6 数据完整性     — 2 条 (AIDE)
8.1.4.7 数据保密性     — 2 条 (/tmp 隔离 / nodev/nosuid/noexec)
```

## CIS RHEL 8 L1 覆盖章节

```
1.1.1 Filesystem 模块禁用 — 3 (cramfs/squashfs/udf)
1.2   Software Updates    — 2 (gpg/gpgcheck)
1.4   Bootloader          — 2 (GRUB 密码 + 权限)
1.5   Process Hardening   — 2 (core dump / ASLR)
1.6   SELinux             — 4 (安装/不禁用/targeted/Enforcing)
2.1   Inetd Services      — 1
2.2   Special Services    — 5 (NTP/X/rsync 等)
3.1   Network             — 2 (IPv6/Wireless)
3.2   Network Parameters  — 4 (Source Routed/ICMP redirects/martians)
3.4   Firewall            — 1
4.1   Auditing            — 2 (auditd 安装/启用)
4.2   Logging             — 2 (rsyslog)
5.1   Cron                — 2
5.2   SSH                 — 8 (sshd_config 关键项)
6.1   File Permissions    — 2 (/etc/passwd /etc/shadow)
```

## 测试

```sh
# Agent 端跑基线
mxsec-baseline-plugin --policy plugins/baseline/config/dengbao/dengbao-l3-rhel.json
mxsec-baseline-plugin --policy plugins/baseline/config/cis-rhel/cis-rhel8-l1.json
```

## 后续 PR 路线

- MVP-2c: Windows Server 2019/2022 基线 (~100 条)
- M1-3b: 中间件扩到 160 (Redis/Postgres/RabbitMQ/Kafka)
- M2:    Ubuntu 22.04 等保规则 (DB_L3_UB_*)
- M2:    K8s CIS Benchmark v1.27 (120 条)
