// npatch/bitbucket_envinj.c — CVE-2022-36804 Atlassian Bitbucket env injection (P5-1)
//
// 漏洞: rest/api/latest/projects/{p}/repos/{r}/archive 通过 git archive --output 注入 shell.
//
// 虚拟补丁: URI 匹配 + query 含 prefix=/at=/path= shell metacharacter (`;|`|`$()`).


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14

struct bitbucket_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u8  has_uri;
    __u8  has_meta;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} bitbucket_events SEC(".maps");

static __always_inline int find(const char *buf, int len, const char *p, int plen) {
    if (plen > 40 || len < plen) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_SCAN - 40; i++) {
        if (i + plen > len) break;
        int m = 1;
        #pragma unroll
        for (int j = 0; j < 40; j++) {
            if (j >= plen) break;
            if (buf[i + j] != p[j]) { m = 0; break; }
        }
        if (m) return 1;
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int scan_bitbucket(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 uri = find(buf, len, "/repos/", 7) && find(buf, len, "/archive", 8) ? 1 : 0;
    __u8 meta = 0;
    if (find(buf, len, "$(", 2) || find(buf, len, "%3B", 3) ||
        find(buf, len, "%7C", 3) || find(buf, len, "%60", 3)) meta = 1;
    if (!(uri && meta)) return 1;

    struct bitbucket_event *e = bpf_ringbuf_reserve(&bitbucket_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->has_uri = uri;
    e->has_meta = meta;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
