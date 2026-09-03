// npatch/spring4shell.c - Spring4Shell (CVE-2022-22965) HTTP body 模式阻断 (P3-7)
//
// 攻击模式: POST body 含 class.module.classLoader.xxxx 绑定参数链
//
// 检测 pattern:
//   class.module.classLoader.
//   class[module][classLoader]
//   class%2Emodule%2EclassLoader  (URL 编码)
//
// 命中 → SK_DROP, 业务侧表现 HTTP 中断 (类 SSL handshake fail).


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PAYLOAD_SCAN 384  // P0-2 缩到 384
#define ETH_HLEN 14
#define IPPROTO_TCP 6

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} npatch_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 32);
} rules_enabled SEC(".maps");

#define RULE_SPRING4SHELL 22965

// match_spring4shell: 三种 pattern 任一命中即返回 1.
static __always_inline int match_spring4shell(const __u8 *data, int len) {
    if (len < 30) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_PAYLOAD_SCAN - 30; i++) {
        if (i + 30 > len) break;
        // Pattern 1: class.module.classLoader.
        // 'c','l','a','s','s','.','m','o','d','u','l','e','.','c','l','a','s','s','L','o','a','d','e','r','.'
        if ((data[i] == 'c' || data[i] == 'C') &&
            (data[i+1] == 'l' || data[i+1] == 'L') &&
            data[i+2] == 'a' && data[i+3] == 's' && data[i+4] == 's' &&
            data[i+5] == '.' &&
            (data[i+6] == 'm' || data[i+6] == 'M') &&
            data[i+7] == 'o' && data[i+8] == 'd' && data[i+9] == 'u' && data[i+10] == 'l' && data[i+11] == 'e' &&
            data[i+12] == '.' &&
            (data[i+13] == 'c' || data[i+13] == 'C') &&
            (data[i+14] == 'l' || data[i+14] == 'L') &&
            data[i+15] == 'a' && data[i+16] == 's' && data[i+17] == 's' &&
            (data[i+18] == 'L' || data[i+18] == 'l') &&
            data[i+19] == 'o' && data[i+20] == 'a' && data[i+21] == 'd' && data[i+22] == 'e' && data[i+23] == 'r') {
            return 1;
        }
        // Pattern 2: class[module][classLoader]
        if (data[i] == 'c' && data[i+1] == 'l' && data[i+2] == 'a' && data[i+3] == 's' && data[i+4] == 's' &&
            data[i+5] == '[' && data[i+6] == 'm' && data[i+7] == 'o') {
            return 1;
        }
        // Pattern 3: class%2Emodule (URL encoded .)
        if (data[i] == 'c' && data[i+1] == 'l' && data[i+2] == 'a' && data[i+3] == 's' && data[i+4] == 's' &&
            data[i+5] == '%' && data[i+6] == '2' &&
            (data[i+7] == 'E' || data[i+7] == 'e') &&
            data[i+8] == 'm' && data[i+9] == 'o') {
            return 1;
        }
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int npatch_spring4shell_filter(struct __sk_buff *skb) {
    if (skb->family != 2) return 1;
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    if (data + ETH_HLEN + 20 > data_end) return 1;

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
    if (dst_port != 80 && dst_port != 8080 && dst_port != 443 && dst_port != 8443) {
        return 1;
    }

    __u32 rule_id = RULE_SPRING4SHELL;
    __u8 *enabled = bpf_map_lookup_elem(&rules_enabled, &rule_id);
    if (!enabled || *enabled == 0) return 1;

    __u32 tcp_header_len = ((tcph->doff_res >> 4) & 0x0F) * 4;
    void *payload = tcp + tcp_header_len;
    int payload_len = (int)((__u8 *)data_end - (__u8 *)payload);
    if (payload_len <= 0) return 1;
    if (payload_len > MAX_PAYLOAD_SCAN) payload_len = MAX_PAYLOAD_SCAN;

    if (!match_spring4shell(payload, payload_len)) return 1;

    struct npatch_event *ev = bpf_ringbuf_reserve(&npatch_events, sizeof(*ev), 0);
    if (ev) {
        ev->ts_ns = bpf_ktime_get_ns();
        ev->cgroup_id = (__u32)bpf_get_current_cgroup_id();
        ev->src_ip = iph->saddr;
        ev->dst_ip = iph->daddr;
        ev->src_port = bpf_ntohs(tcph->source);
        ev->dst_port = dst_port;
        ev->rule_id = rule_id;
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            if (i >= payload_len) break;
            ev->matched_payload[i] = ((__u8 *)payload)[i];
        }
        bpf_ringbuf_submit(ev, 0);
    }
    return 0;
}
