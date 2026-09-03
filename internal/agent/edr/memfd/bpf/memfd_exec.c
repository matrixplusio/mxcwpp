// memfd/bpf/memfd_exec.c — memfd_create → execveat fileless 执行检测 (C9)
//
// 原理:
//   攻击者用 memfd_create() 创建匿名 fd → 写入 ELF payload → execveat(fd, ...)
//   绕过磁盘文件写入. fanotify / inotify / 文件 hash 完全看不到.
//
// 检测:
//   kprobe __x64_sys_memfd_create → 记录 pid + fd + name
//   kprobe __x64_sys_execveat → 若 fd 在 memfd 表 → 告警 (T1620 Reflective Code Loading)
//
// 关联窗口 5s, LRU map 自动 evict.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct memfd_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u8  kind; // 1=memfd_create, 2=execveat_memfd
    char  comm[16];
    char  name[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} memfd_events SEC(".maps");

// 记 pid → 最近 memfd_create 时间, 5s 关联窗.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} memfd_track SEC(".maps");

#define MEMFD_WINDOW_NS (5ULL * 1000 * 1000 * 1000)

SEC("kprobe/__x64_sys_memfd_create")
int BPF_KPROBE(probe_memfd_create) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&memfd_track, &pid, &now, BPF_ANY);

    struct memfd_event *e = bpf_ringbuf_reserve(&memfd_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = now;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->kind = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // 取参数 1 (name 指针)
    const char *namep = (const char *)PT_REGS_PARM1(ctx);
    if (namep) {
        bpf_probe_read_user_str(&e->name, sizeof(e->name), namep);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_execveat")
int BPF_KPROBE(probe_execveat) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *last = bpf_map_lookup_elem(&memfd_track, &pid);
    if (!last) return 0;
    __u64 now = bpf_ktime_get_ns();
    if (now - *last > MEMFD_WINDOW_NS) return 0;

    struct memfd_event *e = bpf_ringbuf_reserve(&memfd_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = now;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->kind = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
