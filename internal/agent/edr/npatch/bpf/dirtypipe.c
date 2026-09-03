// npatch/dirtypipe.c — CVE-2022-0847 DirtyPipe 虚拟补丁 (P4-9)
//
// 漏洞机制:
//   pipe_buffer.flags 未初始化, 可继承 PIPE_BUF_FLAG_CAN_MERGE,
//   导致 splice() 把 page cache 内容塞进可合并的 pipe buffer,
//   后续 write(pipe) 直接覆写 page cache → 修改任意只读文件.
//
// 虚拟补丁策略:
//   - kprobe sys_splice 入口: 记录 pid → "已 splice"
//   - kprobe sys_write 入口: 若 fd 是 pipe 且 pid 在 splice 表
//     → 上报事件, observe 模式只记不拦
//
// 真正的内核补丁是在 pipe_buf_init 清零 flags. 这里只检测异常组合,
// 给 SOC 留响应窗口 (隔离主机 / 杀链 / 拉证据).
//
// 严格 read-only RASP 哲学 (Sprint 4 PR63): Action=nil, 不阻塞业务.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct dirtypipe_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u8  kind;   // 1=splice, 2=suspicious_write
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} dirtypipe_events SEC(".maps");

// pid → 最近 splice 时间戳 (ns), 用于关联后续 write.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} recent_splice SEC(".maps");

#define SPLICE_WINDOW_NS (5ULL * 1000 * 1000 * 1000)  // 5 秒关联窗口

SEC("kprobe/__x64_sys_splice")
int BPF_KPROBE(probe_splice) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&recent_splice, &pid, &now, BPF_ANY);

    struct dirtypipe_event *e = bpf_ringbuf_reserve(&dirtypipe_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = now;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->kind = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(probe_write) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u64 *last_splice = bpf_map_lookup_elem(&recent_splice, &pid);
    if (!last_splice) return 0;
    __u64 now = bpf_ktime_get_ns();
    if (now - *last_splice > SPLICE_WINDOW_NS) return 0;

    struct dirtypipe_event *e = bpf_ringbuf_reserve(&dirtypipe_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = now;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->kind = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
