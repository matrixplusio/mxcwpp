# 基线策略配置

本目录是基线插件的策略集，按合规框架 / 适用对象分目录存放。

> 下表由实际文件生成（2026-08-01 核实）：**30 个策略，614 条规则**。
> 改动策略文件后请同步此表——`internal/deploy/docs_sync_test.go` 会校验总数是否一致。

## 策略清单

| 文件 | 名称 | 适用 OS | 规则数 |
|---|---|---|---|
| `cis/centos.json` | CentOS 安全基线（CIS + 等保 2.0）| centos / rocky / almalinux / oracle | 34 |
| `cis/debian.json` | Debian 安全基线（CIS + 等保 2.0）| debian | 24 |
| `cis/ubuntu.json` | Ubuntu 安全基线（CIS + 等保 2.0）| ubuntu | 24 |
| `cis-docker/cis-docker.json` | CIS Docker Benchmark（Host + Daemon + Container）| centos / rocky / almalinux / rhel | 29 |
| `cis-k8s/cis-k8s-v1.27.json` | CIS Kubernetes Benchmark v1.27 | k8s | 61 |
| `cis-rhel/cis-rhel8-l1.json` | CIS RHEL 8 Benchmark Level 1 Server | centos / rocky / almalinux / rhel | 40 |
| `dengbao/dengbao-l3-rhel.json` | 等保 2.0 三级 — RHEL 系 | centos / rocky / almalinux / rhel | 40 |
| `dengbao/dengbao-l3-ubuntu.json` | 等保 2.0 三级 — Ubuntu/Debian | ubuntu / debian | 30 |
| `general/account-security.json` | 账户安全 | 通用 Linux | 23 |
| `general/audit-logging.json` | 审计日志配置 | 通用 Linux | 27 |
| `general/cron-security.json` | 定时任务安全 | 通用 Linux | 10 |
| `general/file-integrity.json` | 文件完整性检查 | 通用 Linux | 4 |
| `general/file-permissions.json` | 关键文件权限 | 通用 Linux | 21 |
| `general/login-banner.json` | 登录横幅 | 通用 Linux | 9 |
| `general/mac-security.json` | 强制访问控制（SELinux/AppArmor）| 通用 Linux | 7 |
| `general/network-protocols.json` | 网络协议安全 | 通用 Linux | 7 |
| `general/password-policy.json` | 密码策略 | 通用 Linux | 17 |
| `general/secure-boot.json` | 安全启动 | 通用 Linux | 7 |
| `general/service-status.json` | 系统服务状态 | 通用 Linux | 26 |
| `general/ssh-baseline.json` | SSH 安全配置 | 通用 Linux | 24 |
| `general/sysctl-security.json` | 内核安全参数 | 通用 Linux | 30 |
| `middleware/apache.json` | Apache HTTP Server | 通用 Linux | 12 |
| `middleware/kafka.json` | Apache Kafka | 通用 Linux | 10 |
| `middleware/mongodb.json` | MongoDB | 通用 Linux | 10 |
| `middleware/mysql.json` | MySQL | 通用 Linux | 14 |
| `middleware/nginx.json` | Nginx | 通用 Linux | 12 |
| `middleware/postgresql.json` | PostgreSQL | 通用 Linux | 10 |
| `middleware/redis.json` | Redis | 通用 Linux | 10 |
| `middleware/tomcat.json` | Apache Tomcat | 通用 Linux | 12 |
| `windows/win-server-2019.json` | Windows Server 2019/2022（CIS + 等保 2.0）| windows | 30 |

## 等保 2.0 三级覆盖维度

`dengbao/` 下策略按 GB/T 22239-2019 章节组织：

```
8.1.4.1 身份鉴别       口令策略 / 空口令 / 登录失败处理
8.1.4.2 访问控制       sudo / umask / 关键文件权限 / UID 唯一性
8.1.4.3 安全审计       auditd / rsyslog / 日志保留期
8.1.4.4 入侵防范       服务最小化 / SSH 加固 / 网络参数 / 防火墙 / SELinux
8.1.4.5 恶意代码防范   ClamAV 安装与病毒库时效
8.1.4.6 数据完整性     AIDE
8.1.4.7 数据保密性     /tmp 独立挂载 / nodev,nosuid,noexec
```

## CIS RHEL 8 L1 覆盖章节

```
1.1.1 Filesystem 模块禁用   cramfs / squashfs / udf
1.2   Software Updates      gpgcheck
1.4   Bootloader            GRUB 密码与权限
1.5   Process Hardening     core dump / ASLR
1.6   SELinux               安装 / targeted / Enforcing
2.1-2.2 Services            inetd / NTP / X / rsync
3.1-3.4 Network             IPv6 / 无线 / 源路由 / ICMP 重定向 / 防火墙
4.1-4.2 Audit & Logging     auditd / rsyslog
5.1-5.2 Cron & SSH          cron 权限 / sshd_config 关键项
6.1   File Permissions      /etc/passwd / /etc/shadow
```

## 本地执行

```sh
mxcwpp-baseline-plugin --policy plugins/baseline/config/dengbao/dengbao-l3-rhel.json
mxcwpp-baseline-plugin --policy plugins/baseline/config/cis-rhel/cis-rhel8-l1.json
```
