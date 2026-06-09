// privilege.c — BPF programs for privilege escalation event collection (M1-1).
//
// Hooks (kprobe based; works on kernel >= 5.4):
//
//   kprobe/commit_creds          — UID/GID 切换的真实入口, 抓所有提权
//   kprobe/__x64_sys_setreuid    — setreuid 系统调用 (含 setresuid 路径)
//   kprobe/__x64_sys_setregid    — setregid / setresgid
//   kprobe/__x64_sys_ptrace      — ptrace 注入 (T1055.008/T1059)
//   kprobe/__x64_sys_mount       — mount 调用 (容器逃逸 T1611)
//   kprobe/security_kernel_module_request — LKM 加载 (Rootkit T1547.006)
//
// 选择 commit_creds 而非 setuid 的原因:
//   setuid 系列只覆盖显式系统调用; commit_creds 是内核唯一入口,
//   抓 capability 变更 / SUID 提权 / NS 切换 等所有路径。
//
// 选择 security_kernel_module_request 而非 init_module 的原因:
//   modprobe / autoload / udev 触发的加载也都走此 LSM hook, 覆盖更全。
//
// 字段对齐 Go 端 PrivilegeEvent struct (见 ebpf_privilege.go); 改字段需同步。

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Privilege event payload.
struct privilege_event {
	__u32  event_type;
	__u32  pid;
	__u32  tgid;
	__u32  ppid;
	__u32  old_uid;
	__u32  new_uid;
	__u32  old_gid;
	__u32  new_gid;
	__u32  target_pid;          // ptrace 时的 target
	__u64  cap_effective;       // capability mask after change
	__u64  timestamp_ns;
	__u8   comm[TASK_COMM_LEN];
	__u8   payload[256];        // mount source/target / module name
};

// Perf buffer.
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} priv_events SEC(".maps");

// Per-CPU scratch (privilege_event ~328 bytes 超 BPF 512 栈预算; 安全起见用 scratch).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct privilege_event);
	__uint(max_entries, 1);
} priv_scratch SEC(".maps");

static __always_inline struct privilege_event *get_scratch(void) {
	__u32 zero = 0;
	return bpf_map_lookup_elem(&priv_scratch, &zero);
}

static __always_inline void fill_common(struct privilege_event *e, __u32 etype) {
	e->event_type = etype;
	e->timestamp_ns = bpf_ktime_get_ns();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = (__u32)pid_tgid;
	e->tgid = (__u32)(pid_tgid >> 32);
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	e->ppid = BPF_CORE_READ(parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// commit_creds(struct cred *new) — UID/GID/cap 切换唯一入口.
SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds, struct cred *new_creds) {
	struct privilege_event *e = get_scratch();
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_common(e, EVENT_PRIV_COMMIT_CREDS);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	const struct cred *old = BPF_CORE_READ(task, cred);
	e->old_uid = BPF_CORE_READ(old, uid.val);
	e->old_gid = BPF_CORE_READ(old, gid.val);
	e->new_uid = BPF_CORE_READ(new_creds, uid.val);
	e->new_gid = BPF_CORE_READ(new_creds, gid.val);
	e->cap_effective = BPF_CORE_READ(new_creds, cap_effective.cap[0]);

	// 仅当 UID/GID 真切换 → 上报 (commit_creds 高频, 否则噪声大)
	if (e->old_uid == e->new_uid && e->old_gid == e->new_gid) {
		return 0;
	}
	bpf_perf_event_output(ctx, &priv_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

// setreuid 系统调用.
SEC("kprobe/__x64_sys_setreuid")
int BPF_KPROBE(kprobe_sys_setreuid, struct pt_regs *regs) {
	struct privilege_event *e = get_scratch();
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_common(e, EVENT_PRIV_SETUID);
	// PT_REGS_PARM1/2 from pt_regs (x86_64 calling convention).
	e->new_uid = (__u32)PT_REGS_PARM2_CORE(regs);
	bpf_perf_event_output(ctx, &priv_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

// setregid 系统调用.
SEC("kprobe/__x64_sys_setregid")
int BPF_KPROBE(kprobe_sys_setregid, struct pt_regs *regs) {
	struct privilege_event *e = get_scratch();
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_common(e, EVENT_PRIV_SETGID);
	e->new_gid = (__u32)PT_REGS_PARM2_CORE(regs);
	bpf_perf_event_output(ctx, &priv_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

// ptrace 系统调用. PT_REGS_PARM1 = request, PT_REGS_PARM2 = pid.
SEC("kprobe/__x64_sys_ptrace")
int BPF_KPROBE(kprobe_sys_ptrace, struct pt_regs *regs) {
	struct privilege_event *e = get_scratch();
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_common(e, EVENT_PRIV_PTRACE);
	e->target_pid = (__u32)PT_REGS_PARM2_CORE(regs);
	bpf_perf_event_output(ctx, &priv_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

// mount 系统调用. 抓 source + target + filesystemtype.
SEC("kprobe/__x64_sys_mount")
int BPF_KPROBE(kprobe_sys_mount, struct pt_regs *regs) {
	struct privilege_event *e = get_scratch();
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_common(e, EVENT_PRIV_MOUNT);
	const char *source = (const char *)PT_REGS_PARM1_CORE(regs);
	const char *target = (const char *)PT_REGS_PARM2_CORE(regs);
	if (source) bpf_probe_read_user_str(&e->payload[0], 128, source);
	if (target) bpf_probe_read_user_str(&e->payload[128], 128, target);
	bpf_perf_event_output(ctx, &priv_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

// LKM 加载. 抓模块名.
SEC("kprobe/security_kernel_module_request")
int BPF_KPROBE(kprobe_kmod_request, char *kmod_name) {
	struct privilege_event *e = get_scratch();
	if (!e) return 0;
	__builtin_memset(e, 0, sizeof(*e));
	fill_common(e, EVENT_PRIV_KMOD_LOAD);
	if (kmod_name) bpf_probe_read_kernel_str(&e->payload[0], 64, kmod_name);
	bpf_perf_event_output(ctx, &priv_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}
