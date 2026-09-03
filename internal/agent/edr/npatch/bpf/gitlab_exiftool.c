// npatch/gitlab_exiftool.c — CVE-2021-22205 GitLab ExifTool RCE (P6-1)
//
// 漏洞机制:
//   GitLab CE/EE 上传图片走 ExifTool 解 DjVu, DjVu Annotation chunk 注入
//   Perl 代码 RCE.
//
// 虚拟补丁: URI /uploads/user + body 多 part 含 AT&T-FORM:DJVU + Annotation.


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14

struct gitlab_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u8  hit;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} gitlab_events SEC(".maps");

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
int scan_gitlab(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 uri = (find(buf, len, "/uploads/user", 13) ||
                find(buf, len, "/api/v4/projects", 16)) ? 1 : 0;
    __u8 djvu = (find(buf, len, "FORM\x00\x00\x00", 7) &&
                 (find(buf, len, "DJVU", 4) || find(buf, len, "ANTa", 4))) ? 1 : 0;
    if (!(uri && djvu)) return 1;

    struct gitlab_event *e = bpf_ringbuf_reserve(&gitlab_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->hit = 1;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
