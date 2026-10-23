// process.c — BPF programs for process event collection.
//
// Hooks:
//   raw_tracepoint/sched_process_exec — fires on execve() completion
//   raw_tracepoint/sched_process_exit — fires on process/thread exit
//
// Why raw_tracepoint instead of tracepoint:
//   Raw tracepoints give direct access to kernel struct pointers (task_struct,
//   linux_binprm) without the stable tracepoint ABI overhead. Combined with
//   CO-RE, this provides both performance and portability.
//
// Why perf buffer instead of ring buffer:
//   Ring buffer (BPF_MAP_TYPE_RINGBUF) requires kernel >= 5.8.
//   Perf buffer works on kernel >= 5.4 (our minimum target).
//   The performance difference is negligible for our event rate (~400 EPS).
//
// Stack usage: process_event (~812 bytes) exceeds the BPF 512-byte stack limit.
//   We use a per-CPU array map (event_scratch) as scratch buffer instead.

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ----- Maps (process-specific) -----

// Perf buffer for delivering process events to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Per-CPU scratch buffer for building process_event (exceeds 512-byte stack limit).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_event);
} event_scratch SEC(".maps");

// PIDs to skip (agent self, child plugins). Populated from Go side.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} whitelist_pids SEC(".maps");

// Dynamic degradation level (0=normal, 1-3=degraded). Updated by Go side.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} config_map SEC(".maps");

// get_degrade_level reads current degradation level from config_map.
static __always_inline __u32 get_degrade_level(void) {
	__u32 zero = 0;
	__u32 *level = bpf_map_lookup_elem(&config_map, &zero);
	return level ? *level : 0;
}

// ----- Helpers -----

// get_event_buf returns a zeroed process_event from the per-CPU scratch buffer.
static __always_inline struct process_event *get_event_buf(void) {
	__u32 zero = 0;
	struct process_event *evt = bpf_map_lookup_elem(&event_scratch, &zero);
	if (evt)
		__builtin_memset(evt, 0, sizeof(*evt));
	return evt;
}

// read_cmdline reads the process command line from user memory into buf.
// task->mm->arg_start .. arg_end holds the original argv strings (NUL-separated).
// NUL-to-space conversion is done on the Go side to keep BPF code simple.
static __always_inline void read_cmdline(struct task_struct *task, char *buf, __u32 buf_size) {
	struct mm_struct *mm;
	unsigned long arg_start, arg_end;

	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return;

	arg_start = BPF_CORE_READ(mm, arg_start);
	arg_end   = BPF_CORE_READ(mm, arg_end);
	if (arg_start == 0 || arg_end <= arg_start)
		return;

	// Compute length and clamp to buffer size.
	// The &= mask satisfies the BPF verifier that len is bounded and non-negative.
	unsigned long len = arg_end - arg_start;
	if (len >= buf_size)
		len = buf_size - 1;
	len &= (MAX_CMDLINE - 1);

	bpf_probe_read_user(buf, len, (void *)arg_start);
	buf[len] = '\0';
}

// ----- sched_process_exec -----
//
// Raw tracepoint args for sched_process_exec:
//   args[0] = struct task_struct *p         (the new task after exec)
//   args[1] = pid_t old_pid                (pid before exec — usually same)
//   args[2] = struct linux_binprm *bprm    (binary info: path, argv, etc.)

SEC("raw_tracepoint/sched_process_exec")
int tracepoint_sched_process_exec(struct bpf_raw_tracepoint_args *ctx) {
	struct task_struct *task;
	struct linux_binprm *bprm;

	task = (struct task_struct *)ctx->args[0];
	bprm = (struct linux_binprm *)ctx->args[2];

	__u32 tgid = BPF_CORE_READ(task, tgid);

	// Fast path: skip whitelisted PIDs
	if (is_whitelisted(&whitelist_pids, tgid))
		return 0;

	// Get per-CPU scratch buffer (avoids 512-byte BPF stack limit)
	struct process_event *evt = get_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_PROCESS_EXEC;
	evt->pid        = BPF_CORE_READ(task, pid);
	evt->tgid       = tgid;
	evt->uid        = BPF_CORE_READ(task, real_cred, uid.val);
	evt->gid        = BPF_CORE_READ(task, real_cred, gid.val);
	evt->start_ts   = bpf_ktime_get_ns();

	// Parent tgid
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		evt->ppid = BPF_CORE_READ(parent, tgid);

	// Container detection
	evt->in_container = detect_container(task);

	// comm (task name, max 16 bytes)
	BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);

	// Executable path from linux_binprm->filename
	const char *filename = BPF_CORE_READ(bprm, filename);
	if (filename)
		bpf_probe_read_kernel_str(evt->filename, sizeof(evt->filename), filename);

	// cmdline from task->mm->arg_start (user-space memory)
	read_cmdline(task, evt->cmdline, MAX_CMDLINE);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}

// ----- sched_process_exit -----
//
// Raw tracepoint args for sched_process_exit:
//   args[0] = struct task_struct *p    (the exiting task)
//
// We only emit events for thread group leaders (pid == tgid) to avoid
// noise from individual thread exits.

SEC("raw_tracepoint/sched_process_exit")
int tracepoint_sched_process_exit(struct bpf_raw_tracepoint_args *ctx) {
	struct task_struct *task;

	task = (struct task_struct *)ctx->args[0];

	__u32 pid  = BPF_CORE_READ(task, pid);
	__u32 tgid = BPF_CORE_READ(task, tgid);

	// Only report thread group leader exits (the main "process" exit).
	// Individual thread exits are noise for EDR purposes.
	if (pid != tgid)
		return 0;

	// Degradation level 3: only process_exec, skip process_exit
	if (get_degrade_level() >= 3)
		return 0;

	// Fast path: skip whitelisted PIDs
	if (is_whitelisted(&whitelist_pids, tgid))
		return 0;

	// Get per-CPU scratch buffer
	struct process_event *evt = get_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_PROCESS_EXIT;
	evt->pid        = pid;
	evt->tgid       = tgid;
	evt->exit_code  = BPF_CORE_READ(task, exit_code) >> 8;  // extract real exit code
	evt->start_ts   = bpf_ktime_get_ns();

	// Parent tgid
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		evt->ppid = BPF_CORE_READ(parent, tgid);

	// Container detection
	evt->in_container = detect_container(task);

	// comm
	BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);

	// filename and cmdline not meaningful for exit events — left zeroed by get_event_buf().

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}
