// npatch/imagemagick.c — CVE-2016-3714 ImageTragick RCE (P5-1)
//
// 漏洞机制:
//   ImageMagick 解析 MSL / SVG / MVG 时未过滤 url:, https:, mvg: scheme,
//   触发 system() 调用.
//
// 虚拟补丁:
//   uprobe libMagickCore-7.so:ReadImage 调用前用户态参数扫描 (本 .c 是 sketch),
//   或走 cgroup_skb 抓 multipart upload, 扫 body 含 mvg:|msl:|https:|url:( 的
//   组合 + magick 特定字串.


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14

struct imagemagick_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u8  scheme;  // 1=mvg, 2=msl, 3=url(, 4=https://...|
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} imagemagick_events SEC(".maps");

static __always_inline int scan(const char *buf, int len, const char *p, int plen) {
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
int scan_imagemagick(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 hit = 0;
    if (scan(buf, len, "mvg:", 4)) hit = 1;
    else if (scan(buf, len, "msl:", 4)) hit = 2;
    else if (scan(buf, len, "url(\"|", 6)) hit = 3;
    else if (scan(buf, len, "https://x.com|", 14)) hit = 4;

    if (!hit) return 1;
    struct imagemagick_event *e = bpf_ringbuf_reserve(&imagemagick_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->scheme = hit;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
