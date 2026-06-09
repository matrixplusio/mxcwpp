// npatch/phpunit_eval.c — CVE-2017-9841 PHPUnit eval-stdin.php RCE (P5-1)
//
// 漏洞路径: /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
// 触发: POST body 含 <?php / <?= 直接 eval.
//
// 虚拟补丁: URI 匹配 + body 头 8 字节扫 <?php / <?=.


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14

struct phpunit_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u16 dst_port;
    __u8  has_uri;
    __u8  has_phptag;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} phpunit_events SEC(".maps");

static __always_inline int substr(const char *buf, int len, const char *needle, int nlen) {
    if (nlen > 40 || len < nlen) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_SCAN - 40; i++) {
        if (i + nlen > len) break;
        int m = 1;
        #pragma unroll
        for (int j = 0; j < 40; j++) {
            if (j >= nlen) break;
            if (buf[i + j] != needle[j]) { m = 0; break; }
        }
        if (m) return 1;
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int scan_phpunit(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 uri = substr(buf, len, "phpunit/src/Util/PHP/eval-stdin.php", 35) ? 1 : 0;
    __u8 tag = (substr(buf, len, "<?php", 5) || substr(buf, len, "<?=", 3)) ? 1 : 0;
    if (!(uri && tag)) return 1;

    struct phpunit_event *e = bpf_ringbuf_reserve(&phpunit_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->has_uri = uri;
    e->has_phptag = tag;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
