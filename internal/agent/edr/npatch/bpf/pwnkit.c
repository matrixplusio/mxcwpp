// npatch/pwnkit.c — CVE-2021-4034 PwnKit (pkexec) 虚拟补丁 (P4-9)
//
// 漏洞机制:
//   pkexec argc=0 时 argv[0] 越界读 envp[0], 攻击者构造特殊环境变量
//   注入 SUID 上下文, getuid()=0 提权.
//
// 虚拟补丁策略:
//   tracepoint sched_process_exec 触发时:
//     - filename ends with "/pkexec"
//     - argc == 0 (或 argv 全空)
//   → 上报事件, observe-only.
//
// 严格 read-only.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct pwnkit_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u32 ppid;
    char  comm[16];
    char  filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} pwnkit_events SEC(".maps");

// tracepoint sched/sched_process_exec ctx layout (内核 5.x).
struct trace_event_raw_sched_process_exec_ctx {
    unsigned long long pad;
    __u32 filename_off;
    __u32 pid;
    __u32 old_pid;
};

static __always_inline int ends_with_pkexec(const char *s, int len) {
    if (len < 7) return 0;
    const char suffix[] = "/pkexec";
    #pragma unroll
    for (int i = 0; i < 7; i++) {
        if (s[len - 7 + i] != suffix[i]) return 0;
    }
    return 1;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec_ctx *ctx) {
    char fname[128] = {0};
    const char *p = (const char *)ctx + (ctx->filename_off & 0xffff);
    long n = bpf_probe_read_kernel_str(&fname, sizeof(fname), p);
    if (n < 7) return 0;
    if (!ends_with_pkexec(fname, n - 1)) return 0;

    // 读 task->mm->arg_start / arg_end 检查 argc.
    // argc==0 检测靠用户态 argv 解析, BPF 里仅做 prefix 检测 + 命中后让 user 拉证据.
    struct pwnkit_event *e = bpf_ringbuf_reserve(&pwnkit_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = ctx->pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->ppid = ctx->old_pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, fname, sizeof(e->filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
