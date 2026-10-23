// npatch/ofbiz_xmlrpc.c — CVE-2023-49070 / CVE-2023-51467 Apache OFBiz XML-RPC RCE (P6-1)
//
// 漏洞机制:
//   OFBiz XML-RPC 端点 (/webtools/control/xmlrpc) 反序列化恶意 XML 触发
//   ysoserial gadget chain.
//
// 虚拟补丁: URI + body methodCall + (CommonsBeanutils/ROME/JdbcRowSet/CommonsCollections) 串.


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14

struct ofbiz_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u8  hit;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ofbiz_events SEC(".maps");

static __always_inline int find(const char *buf, int len, const char *p, int plen) {
    if (plen > 32 || len < plen) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_SCAN - 32; i++) {
        if (i + plen > len) break;
        int m = 1;
        #pragma unroll
        for (int j = 0; j < 32; j++) {
            if (j >= plen) break;
            if (buf[i + j] != p[j]) { m = 0; break; }
        }
        if (m) return 1;
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int scan_ofbiz(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 uri = (find(buf, len, "/webtools/control/xmlrpc", 24) ||
                find(buf, len, "/webtools/control/main", 22)) ? 1 : 0;
    __u8 gadget = 0;
    if (find(buf, len, "CommonsBeanutils", 16)) gadget = 1;
    else if (find(buf, len, "CommonsCollections", 18)) gadget = 2;
    else if (find(buf, len, "JdbcRowSetImpl", 14)) gadget = 3;
    else if (find(buf, len, "ROME", 4) && find(buf, len, "methodCall", 10)) gadget = 4;

    if (!(uri && gadget)) return 1;
    struct ofbiz_event *e = bpf_ringbuf_reserve(&ofbiz_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->hit = gadget;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
