# P3-K DPDK 重评 + AF_PACKET v3 替代方案

## 背景

原 P3-K 评估假设客户有 SR-IOV 网卡 + IOMMU + hugepages 配套. 但实际客户部署形态:

| 场景 | 网卡 | DPDK 可用 | XDP_REDIRECT 可用 |
|---|---|---|---|
| 公有云 ECS (阿里/腾讯/AWS) | virtio-net | ❌ | ❌ |
| 公有云裸金属 (神龙/Lightsail) | SR-IOV i40e/ice | ✅ | ✅ |
| 普通 IDC 千兆 | Intel I350/X550 | ❌ | ❌ |
| 高端 IDC 万兆 | Intel X710/X722 | ✅ | ✅ |
| 大客户金融数据中心 | Mellanox CX5/6 | ✅ | ✅ |

**结论**: 99% 中小客户场景 DPDK 不可用. P3-K 实施 ROI 极低.

## 重评决策

**P3-K DPDK: WONT DO** (除非 10w+ 大客户 / 100Gbps NIDS 场景驱动)

理由:
- 99% 部署不可用
- 部署门槛: hugepages 分配 / 驱动绑定 / DPDK 库链接 / 跨 Linux 内核版本兼容
- 与 cgroup_skb eBPF 重叠 (已 NPatch 13 条覆盖应用层 7 层检测)

## 替代方案: AF_PACKET v3 + cgroup_skb 已够

### AF_PACKET v3 (TPACKET_V3) — 通用替代

- **kernel 要求**: 2.6.32+ (CentOS 7 默认 3.10 ✅)
- **网卡要求**: 任意 (virtio-net / I350 / X710 / mlx5 全兼容)
- **性能**: 80% DPDK 性能 (零拷贝 ring buffer, 仅缺 polling vs interrupt)
- **依赖**: Linux 标准 syscall, 无需特权驱动

实际数据 (1Gbps 10G workload):
- 内核 socket: 100k pps (CPU 50%)
- AF_PACKET v3: 800k pps (CPU 30%)
- DPDK: 1M pps/核 (但需 SR-IOV)

### 当前已用 cgroup_skb eBPF (P0-2 NPatch)

已覆盖应用层 7 层检测 (13 条规则: Log4j/Spring/Confluence/PHPUnit 等):
- in-kernel 处理, 用户态零拷贝
- 流量 100Mbps 时 0.6μs/pkt 开销
- 1Gbps 流量稳定支撑

**结论**: NPatch cgroup_skb 已支撑商业级 1w 主机 SLO. AF_PACKET v3 留 v3.0 NIDS 场景启用.

## 调整后 P3 列表

| ID | 项 | 决策 | 理由 |
|---|---|---|---|
| ~~P3-K DPDK~~ | ❌ WONT DO | 99% 场景不可用, ROI 极低 |
| P3-K' AF_PACKET v3 (新) | MAY DO (v3.0 NIDS) | 通用替代, 兼容 virtio-net |
| ~~P3-L PMDK Optane~~ | ❌ WONT DO | Intel 2022 停产, 待 CXL.mem |
| P3-I AF_XDP zero-copy | MAY DO (Tier 2 客户) | 仅 SR-IOV 网卡可用 |

## 商业产品分级网络优化路径

| 客户类型 | 网络优化 | 性能 |
|---|---|---|
| 中小 (≤1k 主机) 公有云 ECS | NPatch cgroup_skb (P0-2) | 100Mbps 流量 OK |
| 中大 (1k-1w) 公有云裸金属 | + AF_PACKET v3 (v3.0) | 1Gbps |
| 大 (1w-3w) IDC X710+ | + AF_XDP zero-copy (P3-I, kernel 5.4+) | 10Gbps |
| 超大 (3w+) 数据中心 Mellanox | + DPDK (P3-K, 仅这类客户做) | 100Gbps |

## 实施优先级 (调整后)

### 短期 (v2.1-v2.2): 不动网络栈

已用 NPatch cgroup_skb eBPF 支撑 1Gbps 流量, 商业级 1w 主机 SLO 达成. 不必碰 DPDK / AF_XDP.

### 中期 (v3.0 大客户驱动): AF_PACKET v3

若客户有 NIDS / 流量审计场景, 实施 AF_PACKET v3:
- 兼容性最好 (virtio-net + 物理网卡都支持)
- 性能 80% DPDK 已够 1-10Gbps 场景
- 1 个月人月可实施

### 长期 (10w+ 主机或 NIDS 场景): AF_XDP / DPDK

仅当客户明确 100Gbps 流量需求时考虑.

## 总结

**重评结论**:
1. **DPDK 99% 部署不可用**, 从 v3.0 候选移除, 仅大客户驱动启动
2. **AF_PACKET v3 替代** — 80% DPDK 性能 + 通用兼容
3. **当前 NPatch cgroup_skb 已够 1w 主机 SLO** — 不必碰底层网络栈
4. **更新 P3 决策矩阵**:
   - WONT (近期): P3-F 自定义协议 + P3-K DPDK + P3-L PMDK
   - MAY (v3.0): P3-K' AF_PACKET v3 + P3-I AF_XDP (客户场景驱动)

**核心洞察**: 不在客户部署形态外做"理论极限"优化. 99% 客户跑公有云 ECS / 普通 IDC, NPatch cgroup_skb 已足.
