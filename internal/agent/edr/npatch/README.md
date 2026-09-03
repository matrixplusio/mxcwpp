# NPatch eBPF PoC (P2-16)

ref/06-漏洞 M2-P2-1/2: NPatch 虚拟补丁 eBPF 字节码注入 + 30 条规则。

## 当前进度

| 模块 | 状态 | PR |
|---|---|---|
| Server 规则定义 + 30 条 CVE | ✅ | M1-4 (PR #88) |
| Agent eBPF C 源: Log4j JNDI 阻断 | 🟢 | P2-16 (this) |
| Agent BPF loader (cilium/ebpf) | ❌ | 待 P3 |
| Agent ↔ Server 规则同步通道 | ❌ | 待 P3 |
| 测试覆盖 + benchmark | ❌ | 待 P3 |

## 设计

```
Server NPatch rule (manager/biz/npatch)
  ↓ Kafka mxcwpp.npatch.rules
Agent NPatch rule subscriber
  ↓ 编译 → bpf_map 更新 rules_enabled
内核 cgroup_skb/ingress hook
  ↓ 流量经过
match_jndi_pattern() → SK_DROP / SK_PASS
  ↓ 命中
ringbuf event → Agent userspace
  ↓ 聚合
gRPC report → AC → Engine → Alert
```

## 当前 PoC (Log4j JNDI)

文件: `bpf/log4j_jndi.c`

```c
SEC("cgroup_skb/ingress")
int npatch_log4j_filter(struct __sk_buff *skb)
```

匹配 `${jndi:(ldap|rmi|dns)://` pattern, 命中即 SK_DROP.

仅扫:
- IPv4 TCP
- HTTP 端口 (80/8080/443/8443)
- payload 前 512 字节 (BPF verifier 复杂度限制)

性能预算 (待实测):
- 单包延迟 ≤ 5μs (无命中)
- throughput 影响 ≤ 1%

## 限制 (M2 完善)

- 仅明文 HTTP (TLS 流量走 RASP / JNI hook)
- chunked encoding / 大 body 跨多包合并未实现
- 仅 IPv4, IPv6 后续
- ldap:// 大小写 + 简单白空格识别, 复杂 obfuscation 未覆盖

## 编译

```sh
cd internal/agent/edr/npatch
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include/bpf -I bpf \
  -c bpf/log4j_jndi.c -o bpf/log4j_jndi.o

# 加载 (生产 Agent 自动加载)
bpftool prog load bpf/log4j_jndi.o /sys/fs/bpf/npatch_log4j
bpftool cgroup attach /sys/fs/cgroup type cgroup_skb/ingress pinned /sys/fs/bpf/npatch_log4j
```

## 启用规则

```sh
# 通过 Agent 主进程或 bpftool 写 rules_enabled map
bpftool map update pinned /sys/fs/bpf/rules_enabled key 0x4 0xA8 0xBC 0x00 value 0x01
# rule_id 44228 (Log4j) → enabled=1
```

## 后续 PR (P3-* / M2)

- P3-1: NPatch eBPF loader (Go cilium/ebpf 集成)
- P3-2: Spring4Shell (CVE-2022-22965) eBPF hook
- P3-3: Shellshock (CVE-2014-6271) eBPF hook
- P3-4: NPatch eBPF benchmark + 性能 SLO 验证
- M2-P2-1: NPatch UI 配置 + 监控视图
- M2-P2-2: 30 条规则全部上 eBPF (当前仅 Log4j PoC)
