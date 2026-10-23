// npatch/jenkins_scriptconsole.c — Jenkins Script Console + CVE-2024-23897 (P6-1)
//
// 漏洞机制:
//   1. /script (Groovy 控制台) 未授权访问 → RCE
//   2. CVE-2024-23897 CLI args4j arbitrary file read
//
// 虚拟补丁: URI 含 /script + (println Runtime|exec.getRuntime) 或 /cli 路径 + @file 文件读语法.


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14

struct jenkins_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u8  hit;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} jenkins_events SEC(".maps");

static __always_inline int find(const char *buf, int len, const char *p, int plen) {
    if (plen > 24 || len < plen) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_SCAN - 24; i++) {
        if (i + plen > len) break;
        int m = 1;
        #pragma unroll
        for (int j = 0; j < 24; j++) {
            if (j >= plen) break;
            if (buf[i + j] != p[j]) { m = 0; break; }
        }
        if (m) return 1;
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int scan_jenkins(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 hit = 0;
    if (find(buf, len, "/script", 7) && find(buf, len, "Runtime.getRuntime", 18)) hit = 1;
    else if (find(buf, len, "/script", 7) && find(buf, len, "execute", 7)) hit = 2;
    else if (find(buf, len, "/cli?remoting", 13) && find(buf, len, "@/", 2)) hit = 3;
    if (!hit) return 1;

    struct jenkins_event *e = bpf_ringbuf_reserve(&jenkins_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->hit = hit;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
