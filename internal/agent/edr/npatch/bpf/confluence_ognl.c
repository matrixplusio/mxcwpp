// npatch/confluence_ognl.c — CVE-2022-26134 / CVE-2023-22515 Confluence OGNL 注入 (P5-1)
//
// 漏洞机制:
//   Confluence 模板引擎对 ${...} 求值 OGNL 表达式时未隔离, 攻击者构造
//   ${%22freemarker.template.utility.Execute%22} 触发 Runtime.exec.
//
// 虚拟补丁:
//   cgroup_skb/ingress 抓 HTTP 入站, 扫描 URI/body 含 OGNL 关键字串:
//     - %22freemarker.template.utility.Execute%22
//     - org.apache.commons.collections
//     - org.springframework.context.support.FileSystemXmlApplicationContext
//   命中 → ringbuf 上报, observe-only.


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14
#define IPPROTO_TCP 6

struct confluence_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u32 src_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  pattern_id;  // 1=freemarker, 2=commons-collections, 3=spring
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} confluence_events SEC(".maps");

static __always_inline int contains_token(const char *buf, int len, const char *needle, int nlen) {
    if (nlen > MAX_SCAN || len < nlen) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_SCAN - 8; i++) {
        if (i + nlen > len) break;
        int m = 1;
        #pragma unroll
        for (int j = 0; j < 16; j++) {
            if (j >= nlen) break;
            if (buf[i + j] != needle[j]) { m = 0; break; }
        }
        if (m) return 1;
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int scan_confluence(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 hit = 0;
    if (contains_token(buf, len, "freemarker.template", 19)) hit = 1;
    else if (contains_token(buf, len, "org.apache.commons.collections", 30)) hit = 2;
    else if (contains_token(buf, len, "FileSystemXmlApplicationContext", 31)) hit = 3;

    if (!hit) return 1;
    struct confluence_event *e = bpf_ringbuf_reserve(&confluence_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->pattern_id = hit;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
