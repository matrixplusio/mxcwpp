// npatch/atlassian_oauth.c — CVE-2023-22515 / CVE-2024-21683 Confluence OAuth/Macro RCE (P6-1)
//
// 漏洞机制:
//   Confluence Data Center setup wizard 未限管理员注册, 远端可注册新 admin,
//   再通过 OGNL macro 触发 RCE.
//
// 虚拟补丁: URI 命中 /server-info.action + setupComplete=false 组合, 或 /setup/setupadministrator.action
// 上报 ringbuf, observe-only.

#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN

struct atlassian_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u8  hit;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} atlassian_events SEC(".maps");

static __always_inline int find(const char *buf, int len, const char *p, int plen) {
    if (plen > 48 || len < plen) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_SCAN - 48; i++) {
        if (i + plen > len) break;
        int m = 1;
        #pragma unroll
        for (int j = 0; j < 48; j++) {
            if (j >= plen) break;
            if (buf[i + j] != p[j]) { m = 0; break; }
        }
        if (m) return 1;
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int scan_atlassian(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; // P0-2: 早退 非 HTTP 流量
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 hit = 0;
    if (find(buf, len, "/server-info.action", 19) && find(buf, len, "setupComplete=false", 19)) hit = 1;
    else if (find(buf, len, "/setup/setupadministrator.action", 32)) hit = 2;
    else if (find(buf, len, "/plugins/servlet/oauth/users/icon-uri", 37)) hit = 3;
    if (!hit) return 1;

    struct atlassian_event *e = bpf_ringbuf_reserve(&atlassian_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->hit = hit;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
