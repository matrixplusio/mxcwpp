# P3 架构级优化 详细评估

**前置**: P0+P1+P2 共 29 PR 已合 main, 单 region 1w 主机 SLO < 10s 达成.

**目标**: 评估 P3 各项实施成本 / 收益 / 风险, 推荐落地顺序.

**约束**: CentOS 7 默认 kernel 3.10 必须兼容 (大客户群体).

---

## P3 项总览

| ID | 项 | Tier | 人月 | 性能收益 | 兼容性风险 |
|---|---|---|---|---|---|
| P3-A | codegen 替 reflect | 1 | 1.5 | CPU ↓ 30% | 低 |
| P3-B | GC tuning + GOMEMLIMIT | 1 | 0.3 | P99 ↓ 20% | 极低 |
| P3-C | CPU pin + NUMA aware | 1 | 1 | P99 ↓ 30% | 中 (硬件依赖) |
| P3-D | CEL hot path C 重写 cgo | 1 | 3 | CEL 10x | 高 (cgo 部署复杂) |
| P3-E | Apache Arrow + DuckDB OLAP | 1 | 4 | 查询 100x | 中 (双写迁移) |
| P3-F | 自定义二进制协议替 sarama | 1 | 3 | 网络 -20% | 高 (协议 break) |
| P3-G | io_uring async I/O | 2 | 2 | I/O 3x | 中 (kernel 5.6+ only) |
| P3-H | BPF LSM 全套接入 | 2 | 1 (骨架已落) | 安全维度新增 | 中 (kernel 5.7+) |
| P3-I | AF_XDP 零拷贝抓包 | 2 | 4 | 抓包 10x | 高 (kernel 5.4+ + 网卡驱动) |
| P3-J | Rust 重写 Engine 热点 | 1 | 6 | 3x 吞吐 + P99 ↓ 80% | 极高 (双栈维护) |
| P3-K | DPDK 用户态网络栈 | 3 | 6 | 1M pps/核 | 极高 (硬件 + 部署) |
| P3-L | PMDK 持久内存 | 3 | 2 | μs 延迟 | 极高 (Optane 硬件依赖) |

**合计 (Tier 1 全做)**: ~19 人月 → 1 Sprint 团队 5 人 × 4 月

---

## Tier 1 (CentOS 7 默认 3.10 兼容) — 推荐 v2.1-v2.3

### P3-A codegen 替 reflect

**当前痛点**:
- GORM SELECT 反射查 struct 字段 60+ 次/请求 (CPU 烫手)
- sarama 序列化 ProducerMessage 反射拼字段
- json.Marshal/Unmarshal 走 reflect 慢路径

**方案**:
- GORM: 引 `ariga.io/atlas` + 自动生成 `<Model>Scanner.go` (CompileQuery + Scan 直接结构化)
- Kafka: `flatbuffers` 替 sarama protobuf (二进制 codegen, 零反射)
- JSON 热点: `goccy/go-json` (反射缓存) 或 `bytedance/sonic` (汇编加速 SIMD)

**收益**:
- Manager hot path (列表查询) CPU ↓ 30%
- Pipeline JSON 解码 + Marshal: 2x 加速
- 单 Engine 100k EPS → 130k EPS

**风险**:
- sonic 走 AVX2 (Intel Haswell 2013+/AMD Zen+): CentOS 7 默认 ✅
- GORM codegen 需 schema 稳定, 迁移期 N+M 双栈

**实施**:
1. JSON: 全局 import 切换 sonic (1 行改, 3 天验证)
2. GORM scan codegen: 顶层 20 张表 (2 周)
3. 暂不动 sarama (P0-1 Async 已够用)

**ROI**: ⭐⭐⭐⭐⭐ (1.5 人月换 30% CPU, 最高 ROI)

---

### P3-B GC tuning + GOMEMLIMIT

**当前痛点**:
- Go GC 默认 GOGC=100, 堆翻倍触发 GC, 高 EPS 时 GC 频率 5-10 次/s
- Agent OOM 风险 (无 mem 上限)

**方案**:
- Engine/Manager: `GOMEMLIMIT=4GiB GOGC=200` (大 heap 减 GC 频率 50%)
- Agent: `GOMEMLIMIT=200MiB GOGC=100` (严控内存上限, 防 OOM kill)
- 加 runtime debug.SetGCPercent + GOMEMLIMIT 动态调整 API

**收益**:
- Engine P99 ↓ 20% (GC stop-the-world 时间 ↓)
- Agent 内存可预测, 防 K8s OOMKill

**风险**: 极低 — 仅 env 变量调整 + 1 处 runtime call

**实施**: 3 天 (含压测验证)

**ROI**: ⭐⭐⭐⭐⭐ (0.3 人月最快收益)

---

### P3-C CPU pin + NUMA aware

**当前痛点**:
- Engine worker 跨 CPU socket 走 QPI/UPI 延迟翻倍
- Kafka broker 与 Engine 抢同核, context switch 累

**方案**:
- systemd `CPUAffinity=` 绑 Engine 到 NUMA node 0 全核
- Kafka broker 绑 NUMA node 1
- worker pool 用 `golang.org/x/sys/unix.SchedSetaffinity` 绑每 worker 到独立 CPU

**收益**:
- 跨 NUMA 访问 ↓ 80%
- L1/L2 cache 命中率 ↑ 30%
- P99 ↓ 30% (NUMA 机器 32+ 核)

**风险**:
- 单 NUMA 机器无收益 (服务器 CPU 8 核以下)
- 配置写死后 K8s pod 调度受限

**实施**: 1 人月 (含 NUMA 探测 + 配置生成器)

**ROI**: ⭐⭐⭐ (仅 NUMA 大机器)

---

### P3-D CEL hot path C 重写 cgo

**当前痛点**:
- CEL Go runtime 单事件求值 ~50μs (250 规则 = 12ms)
- AST 解释执行慢, 比编译执行慢 5-10x

**方案**:
- 用 Google [cel-cpp](https://github.com/google/cel-cpp) C++ 实现
- cgo 包装为 Go interface
- 热路径 (高频规则前 20%) 走 cel-cpp, 其它仍 Go runtime

**收益**:
- 单规则求值 50μs → 5μs (10x)
- Pipeline 整体延迟 ↓ 60%

**风险**:
- cgo overhead (上下文切换 ~200ns / call) 抵消部分收益
- 跨平台编译复杂 (CentOS 7 glibc 2.17 + Ubuntu 22.04 glibc 2.35 兼容)
- 静态链接 libstdc++ 二进制膨胀 50MB+

**实施**: 3 人月 (含 build pipeline + 跨平台)

**ROI**: ⭐⭐⭐ (CEL 已非瓶颈 — P0-4 分桶 + P0-5 解码一次后)

**建议**: 先看 prod profiling, 若 CEL 仍 >10% CPU 才上, 否则 skip.

---

### P3-E Apache Arrow + DuckDB OLAP

**当前痛点**:
- MySQL 查 alerts 大表 COUNT/GROUP BY 慢 (5M 行 → 8s)
- ClickHouse 复杂 JOIN 性能可, 但部署门槛高 (3 节点起)

**方案**:
- Manager 引入 [DuckDB-Go](https://github.com/marcboeker/go-duckdb) embedded OLAP engine
- 启动时从 MySQL/CH 增量同步到本地 Arrow 列存 (内存 + parquet 持久化)
- 复杂查询 (dashboard / 报表) 走 DuckDB
- 简单 OLTP (host 详情 / alert ack) 仍 MySQL

**收益**:
- 5M 行 COUNT/GROUP BY: 8s → 80ms (100x)
- 单机 Manager 跑 100M 行 OLAP 不需要 ClickHouse 集群

**风险**:
- 双写 + 一致性窗口 (10-60s 延迟容忍)
- DuckDB 单机不分布式 (大集群仍需 CH)
- 内存占用 (1G alerts 列存 ~2GB RAM)

**实施**:
- 4 人月 (含 sync worker + query router + 缓存失效)

**ROI**: ⭐⭐⭐⭐ (Dashboard 用户体验质变)

---

### P3-F 自定义二进制协议替 sarama

**当前痛点**:
- sarama ProducerMessage 头部 60 字节 (key/value/headers + metadata)
- 高 EPS 时 60% 带宽走头部
- protobuf 序列化反射慢

**方案**:
- 自定义 16 字节头部: `[magic 2B][version 1B][type 1B][tenant_id_hash 4B][length 4B][crc32 4B]`
- payload 走 flatbuffers (零拷贝)
- 仅用于 Agent → AC → Engine 内部链路, 外部接口仍 protobuf

**收益**:
- 单消息头部 60B → 16B (-73%)
- 序列化 CPU ↓ 40%
- 网络带宽 ↓ 20%

**风险**:
- 协议 break: 升级时 Agent + Server 必须同步
- 需自实现 codec/ versioning / 兼容层
- 走出生态 (失去 Kafka tooling)

**实施**: 3 人月 (含 codec lib + 双协议过渡期)

**ROI**: ⭐⭐ (P0+P1 后 50k EPS 已支撑 1w 主机, 网络非瓶颈)

**建议**: skip 直到 3w+ 主机规模.

---

### P3-J Rust 重写 Engine 热点

**当前痛点**:
- Go GC 1-5ms STW 影响 P99
- runtime overhead (goroutine scheduler / channel)

**方案**:
- Engine pipeline stage 用 Rust 重写 (CEL / Storyline / ML)
- 与 Go Manager 走 gRPC unix socket
- Cargo workspace + maturin 包装 Python bindings (复用 ML 训练栈)

**收益**:
- 吞吐 3x (无 GC overhead)
- P99 ↓ 80% (无 STW)
- 内存 ↓ 50% (无 runtime + 精确生命周期)

**风险**:
- 团队技能栈分裂 (Go + Rust 双维护)
- 编译 + CI 复杂度翻倍
- Rust 生态 SAML/JWT/ORM 不如 Go 成熟

**实施**: 6 人月 (1 senior Rust 工程师全职)

**ROI**: ⭐⭐⭐⭐ (规模 3w+ 主机时质变, 否则过度工程)

**建议**: v3.0 大客户驱动时启动, 否则 skip.

---

## Tier 2 (需 kernel-ml 5.x, 客户配套升级)

### P3-G io_uring async I/O

- kernel 5.6+ stable
- 单连接 I/O 提升 3x
- 替换 syscall.Read/Write 走 io_uring submit queue
- CentOS 7 客户需先升 ELRepo kernel-ml 5.15 LTS
- **建议**: build tag `iouring`, 默认关, 5.x kernel 自动启用

### P3-H BPF LSM 全套接入

- 已落 C10 (PR201) 骨架
- 真实接入 cilium/ebpf bpf2go: 1 人月
- 6 hook (bprm/inode_create/unlink/socket_connect/mmap_wx) 全启用
- CentOS 7 默认 3.10 fallback 走 kprobe + auditd

### P3-I AF_XDP 零拷贝抓包

- kernel 5.4+ stable
- 100Gbps 流量场景必需
- 网卡驱动需支持 XDP_REDIRECT
- **风险**: i40e / ice / mlx5 支持, 老 Intel 1Gbps 不支持
- **建议**: 仅大客户 / 数据中心场景启用, default 关

---

## Tier 3 (硬件依赖)

### P3-K DPDK 用户态网络栈

- 完全绕过内核 TCP/IP 栈
- 性能 1M pps/核 (理论上限)
- 需 SR-IOV 网卡 + IOMMU
- 部署门槛高 (hugepages 分配 + 驱动绑定)
- **适用**: 超大客户 (10w+ 主机) / 金融行业 NIDS 场景
- **不推荐 v3.0 前实施**

### P3-L PMDK 持久内存

- Intel Optane DC 已停产 (Intel 2022 公告)
- CXL.mem 标准化中 (Sapphire Rapids 2023+)
- **建议**: 跟踪 CXL.mem 标准, 2-3 年后再评估

---

## 推荐落地路线

### v2.1 (1 Sprint = 1 月)

- ✅ **P3-B GC tuning** (3 天, ⭐⭐⭐⭐⭐)
- ✅ **P3-A codegen JSON 切 sonic** (3 天, ⭐⭐⭐⭐⭐)
- ✅ **P3-A codegen GORM scan** (2 周, ⭐⭐⭐⭐)
- ⏸️ **P3-C CPU pin** (仅 NUMA 大机器客户做)

**收益**: 单 Engine 130k EPS, P99 ↓ 20% (1w 主机 < 5s SLO)

### v2.2 (2 Sprint = 2 月)

- ✅ **P3-E Arrow + DuckDB** (4 周, dashboard 用户体验质变)
- ⏸️ **P3-D CEL C 重写** (skip 除非 profiling 显示 CEL >10% CPU)
- ⏸️ **P3-H BPF LSM 真接入** (1 月, Tier 2 客户启用)

**收益**: Dashboard 查询 100x, OLAP 100M 行不需 CH 集群

### v3.0 (大客户驱动, 6 月+)

- ✅ **P3-J Rust 重写 Engine 热点** (6 月, 大客户 3w+ 主机驱动)
- ⏸️ **P3-G io_uring** (kernel 5.x 客户启用)
- ⏸️ **P3-I AF_XDP** (NIDS / 100Gbps 场景)
- ❌ **P3-F 自定义协议** (skip, 网络非瓶颈)
- ❌ **P3-K DPDK** (skip 除非超大客户)
- ❌ **P3-L PMDK** (skip 待 CXL.mem)

**收益**: 单 region 3w-5w 主机, P99 < 5s

---

## 决策矩阵

```
ROI vs 风险 二维分布
                   ROI →
              低         高
       ┌──────────┬──────────┐
   低 │ P3-B/A   │ ⭐ MUST   │
       │          │   P3-A/B │
   风 ├──────────┼──────────┤
   险 │ P3-C/F   │ P3-E/J/D │
       │          │          │
   高 │ P3-K/L   │ P3-G/I/H │
       └──────────┴──────────┘
```

**MUST DO (v2.1)**: P3-B GC tuning + P3-A codegen

**SHOULD DO (v2.2)**: P3-E Arrow/DuckDB + P3-H BPF LSM 真接入

**MAY DO (v3.0)**: P3-J Rust + P3-G io_uring (大客户驱动)

**WONT DO (近期)**: P3-F/K/L (over-engineering)

---

## CentOS 7 客户分级支持

| 客户类型 | 推荐路径 | 性能目标 |
|---|---|---|
| 中小 (≤1k 主机) CentOS 7 默认 | v2.0 GA (P0+P1+P2) | 1k 主机 < 3s |
| 中大 (1k-1w) CentOS 7 默认 | v2.1 (+P3-B+P3-A) | 1w 主机 < 5s |
| 大 (1w-3w) 配合 kernel-ml | v2.2 + ELRepo 升级 | 3w 主机 < 8s |
| 超大 (3w+) RHEL 9 / Ubuntu 22.04 | v3.0 全 P3 | 5w+ 主机 |

---

## 总结建议

1. **立刻可做** (1 周): P3-B GC tuning + P3-A sonic 切换 = 30% CPU ↓
2. **下个 Sprint** (1 月): P3-A GORM codegen + (NUMA 客户) P3-C CPU pin
3. **看市场需求**: 若 3w+ 大客户出现, 启动 P3-J Rust 重写
4. **不做**: P3-F/K/L (ROI 不足 / 硬件依赖 / 协议 break)

P3 不必全做. P0+P1+P2 已支撑 1w 主机 SLO, P3 是边际收益. 实际优化驱动力应来自客户实测瓶颈, 而非预先做完所有项.
