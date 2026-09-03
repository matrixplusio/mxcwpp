// npatch/spring_actuator.c — Spring Boot Actuator 未授权 RCE (P5-1)
//
// 受影响端点:
//   /actuator/env (POST, set property → eval EL)
//   /actuator/gateway/refresh
//   /jolokia/exec/* (JMX MBean exec)
//
// 虚拟补丁: 扫 URI 路径关键串 + POST body 含 spring.cloud.bootstrap.location
// 等危险参数. observe-only.


#include "common_fastpath.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SCAN NPATCH_MAX_SCAN
#define ETH_HLEN 14

struct actuator_event {
    __u64 ts_ns;
    __u32 cgroup_id;
    __u16 dst_port;
    __u8  pattern_id;  // 1=env, 2=gateway, 3=jolokia, 4=cloud-bootstrap
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} actuator_events SEC(".maps");

static __always_inline int find_pattern(const char *buf, int len, const char *pat, int plen) {
    if (plen > 40 || len < plen) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_SCAN - 40; i++) {
        if (i + plen > len) break;
        int m = 1;
        #pragma unroll
        for (int j = 0; j < 40; j++) {
            if (j >= plen) break;
            if (buf[i + j] != pat[j]) { m = 0; break; }
        }
        if (m) return 1;
    }
    return 0;
}

SEC("cgroup_skb/ingress")
int scan_actuator(struct __sk_buff *skb) {
    if (!is_http_inbound(skb)) return 1; /* P0-2 fastpath */
    char buf[MAX_SCAN] = {0};
    int len = skb->len > MAX_SCAN ? MAX_SCAN : skb->len;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, buf, len) < 0) return 1;

    __u8 hit = 0;
    if (find_pattern(buf, len, "/actuator/env", 13)) hit = 1;
    else if (find_pattern(buf, len, "/actuator/gateway", 17)) hit = 2;
    else if (find_pattern(buf, len, "/jolokia/exec", 13)) hit = 3;
    else if (find_pattern(buf, len, "spring.cloud.bootstrap.location", 31)) hit = 4;

    if (!hit) return 1;
    struct actuator_event *e = bpf_ringbuf_reserve(&actuator_events, sizeof(*e), 0);
    if (!e) return 1;
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_skb_cgroup_id(skb);
    e->pattern_id = hit;
    bpf_ringbuf_submit(e, 0);
    return 1;
}
