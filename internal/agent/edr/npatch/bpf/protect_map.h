// protect_map.h — BPF map 给 protect 模式查询 (EDR-2)
//
// cgroup_skb BPF 程序命中规则后, 查 protect_mode map 决定是否 SK_DROP.
//
// userspace (npatch.ProtectController) 通过 bpf2go 注入 mode + rule_override + label_override.
//
// BPF prog 用法:
//
//   if (matched_rule) {
//       __u32 mode = get_protect_mode(rule_id, cgroup_id);
//       if (mode == MODE_PROTECT) {
//           // 上报 ringbuf alert
//           // return 0 → SK_DROP (cgroup_skb 0 = 丢包)
//           return 0;
//       }
//   }
//   return 1; // SK_PASS

#ifndef MXCWPP_NPATCH_PROTECT_MAP_H
#define MXCWPP_NPATCH_PROTECT_MAP_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MODE_OBSERVE 0
#define MODE_PROTECT 1

// 单 rule 的 protect mode 覆盖 (userspace 写, kernel 读).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   // rule_id hash
    __type(value, __u32); // 0=observe 1=protect
} protect_rule_mode SEC(".maps");

// cgroup 的 protect mode 覆盖 (按 cgroup_id; env=prod cluster 全部 protect).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);   // cgroup_id
    __type(value, __u32); // 0=observe 1=protect
} protect_cgroup_mode SEC(".maps");

// 全局默认 (单 entry, key=0).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} protect_default_mode SEC(".maps");

// get_protect_mode 优先级: cgroup > rule > default.
//
// 内联防 verifier 复杂度爆.
static __always_inline __u32 get_protect_mode(__u32 rule_id, __u64 cgroup_id) {
    // 1. cgroup 优先 (业务侧标签强约束)
    __u32 *cg = bpf_map_lookup_elem(&protect_cgroup_mode, &cgroup_id);
    if (cg) return *cg;
    // 2. rule 级 (G6 灰度推送)
    __u32 *rl = bpf_map_lookup_elem(&protect_rule_mode, &rule_id);
    if (rl) return *rl;
    // 3. global default
    __u32 zero = 0;
    __u32 *def = bpf_map_lookup_elem(&protect_default_mode, &zero);
    if (def) return *def;
    return MODE_OBSERVE; // 兜底
}

// should_block — 一行封装给规则文件调用.
//
//   if (matched && should_block(RULE_ID_LOG4J, cgroup_id)) return 0; // SK_DROP
static __always_inline int should_block(__u32 rule_id, __u64 cgroup_id) {
    return get_protect_mode(rule_id, cgroup_id) == MODE_PROTECT;
}

#endif // MXCWPP_NPATCH_PROTECT_MAP_H
