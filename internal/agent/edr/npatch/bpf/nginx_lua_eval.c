// npatch/nginx_lua_eval.c — OpenResty / Kong Lua eval inject (P6-1)
//
// 漏洞机制:
//   ngx_lua 错误地 loadstring(ngx.var.arg_xxx)() 把用户输入当 Lua 代码执行.
//   类似 SSRF + RCE 组合常见于 misconfig.
//
// 虚拟补丁: URI query 含 loadstring( / dofile( / os.execute( / io.popen(.


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14

struct lua_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u8  hit;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} lua_events SEC(".maps");

static __always_inline int find(const char *buf, int len, const char *p, int plen) {
    if (plen > 16 || len < plen) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_SCAN - 16; i++) {
        if (i + plen > len) break;
        int m = 1;
        #pragma unroll
        for (int j = 0; j < 16; j++) {
            if (j >= plen) break;
            if (buf[i + j] != p[j]) { m = 0; break; }
        }
        if (m) return 1;
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int scan_nginx_lua(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 hit = 0;
    if (find(buf, len, "loadstring(", 11)) hit = 1;
    else if (find(buf, len, "os.execute(", 11)) hit = 2;
    else if (find(buf, len, "io.popen(", 9)) hit = 3;
    else if (find(buf, len, "dofile(", 7)) hit = 4;
    else if (find(buf, len, "_G[\"os\"]", 8)) hit = 5;
    if (!hit) return 1;

    struct lua_event *e = bpf_ringbuf_reserve(&lua_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->hit = hit;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
