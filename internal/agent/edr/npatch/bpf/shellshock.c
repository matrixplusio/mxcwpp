// npatch/shellshock.c - Shellshock (CVE-2014-6271) HTTP header 模式阻断 (P3-7)
//
// 攻击模式: HTTP header 含 () { :; }; <command>
//
// 检测 pattern:
//   () { :; };
//   () { :;};
//   () {:;};
//
// 由于 Bash 解析 () { 的容错性, 匹配宽松 (允许中间空格 0-3 个).
//
// 命中 → SK_DROP.


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

#define RULE_SHELLSHOCK 6271

// match_shellshock: 找 () { :; }; pattern (允许 0-3 空格).
static __always_inline int match_shellshock(const __u8 *data, int len) {
    if (len < 10) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_PAYLOAD_SCAN - 10; i++) {
        if (i + 10 > len) break;
        // "() {" prefix 严格匹配
        if (data[i] == '(' && data[i+1] == ')' &&
            data[i+2] == ' ' && data[i+3] == '{') {
            // 后续找 ":;};" (允许空格)
            int j = i + 4;
            int found = 0;
            #pragma unroll
            for (int k = 0; k < 6; k++) {
                if (j + 4 > len) break;
                if (data[j] == ':' && data[j+1] == ';' &&
                    data[j+2] == '}' && data[j+3] == ';') {
                    found = 1;
                    break;
                }
                if (data[j] == ' ') {
                    j++;
                    continue;
                }
                break;
            }
            if (found) return 1;
        }
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int npatch_shellshock_filter(struct __sk_buff *skb) {
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

    __u32 rule_id = RULE_SHELLSHOCK;
    __u8 *enabled = bpf_map_lookup_elem(&rules_enabled, &rule_id);
    if (!enabled || *enabled == 0) return 1;

    __u32 tcp_header_len = ((tcph->doff_res >> 4) & 0x0F) * 4;
    void *payload = tcp + tcp_header_len;
    int payload_len = (int)((__u8 *)data_end - (__u8 *)payload);
    if (payload_len <= 0) return 1;
    if (payload_len > MAX_PAYLOAD_SCAN) payload_len = MAX_PAYLOAD_SCAN;

    if (!match_shellshock(payload, payload_len)) return 1;

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
