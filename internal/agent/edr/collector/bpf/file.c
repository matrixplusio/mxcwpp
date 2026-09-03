// file.c — BPF programs for file event collection.
//
// Hooks (kprobe on LSM hooks, kernel >= 5.4):
//   security_file_open       — file open (filter O_RDONLY)
//   security_inode_rename    — file rename (old + new path)
//   security_inode_unlink    — file delete
//   security_inode_setattr   — chmod/chown (filter ATTR_MODE|ATTR_UID|ATTR_GID)
//
// Why kprobe instead of LSM BPF:
//   LSM BPF (BPF_PROG_TYPE_LSM) requires kernel >= 5.7 + CONFIG_BPF_LSM.
//   kprobe on security_* functions works on kernel >= 5.4 (our minimum target)
//   and doesn't require special kernel config.
//
// Path extraction: walk_dentry() from common.h reads up to 8 dentry levels,
//   writing components separated by \xff. Go side reverses and joins with '/'.
//
// Stack usage: file_event (~564 bytes) exceeds BPF 512-byte stack limit.
//   We use a per-CPU array map (file_event_scratch) as scratch buffer.

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ----- Maps (file-specific) -----

// Perf buffer for delivering file events to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} file_events SEC(".maps");

// Per-CPU scratch buffer for building file_event (exceeds 512-byte stack limit).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_event);
} file_event_scratch SEC(".maps");

// PIDs to skip (agent self, child plugins). Populated from Go side.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} file_whitelist_pids SEC(".maps");

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

// get_file_event_buf returns a file_event from the per-CPU scratch buffer.
//
// Zeroing strategy (BPF verifier safe):
//   - Scalar fields: explicitly zeroed (overwritten by fill_task_info / hook body anyway)
//   - String buffers: only first byte set to NUL. walk_dentry and bpf_probe_read_kernel_str
//     always NUL-terminate their output. Go side reads NUL-terminated strings.
//   - Avoids __builtin_memset on buffers >128 bytes (triggers verifier R2 unbounded
//     memory access on kernel < 5.15).
static __always_inline struct file_event *get_file_event_buf(void) {
	__u32 zero = 0;
	struct file_event *evt = bpf_map_lookup_elem(&file_event_scratch, &zero);
	if (!evt)
		return 0;

	// Zero all scalar fields
	evt->event_type = 0;
	evt->path_mode = 0;
	evt->_pad[0] = 0; evt->_pad[1] = 0;
	evt->pid = 0;
	evt->tgid = 0;
	evt->ppid = 0;
	evt->uid = 0;
	evt->gid = 0;
	evt->inode = 0;
	evt->open_flags = 0;
	evt->new_mode = 0;
	evt->start_ts = 0;
	evt->in_container = 0;

	// Zero comm
	evt->comm[0] = '\0';

	// Zero every slot's first byte in filepath and filepath2.
	// Fixed offsets (i * DENTRY_SLOT_SIZE) are compile-time constants — verifier safe.
	// walk_dentry writes NUL-terminated names into slots it uses.
	// Unused slots stay NUL → Go side stops reading at first empty slot.
	#pragma unroll
	for (int i = 0; i < MAX_DENTRY_DEPTH; i++) {
		evt->filepath[i * DENTRY_SLOT_SIZE] = '\0';
		evt->filepath2[i * DENTRY_SLOT_SIZE] = '\0';
	}

	return evt;
}

// fill_dentry_path fills filepath using walk_dentry. Sets path_mode accordingly.
// Returns 0 on success (at least basename written), -1 on failure.
static __always_inline int fill_dentry_path(struct file_event *evt, struct dentry *dentry) {
	int written = walk_dentry(dentry, evt->filepath);
	if (written > 0) {
		evt->path_mode = PATH_MODE_DENTRY_WALK;
		return 0;
	}

	// Fallback: read basename only
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	if (name) {
		bpf_probe_read_kernel_str(evt->filepath, sizeof(evt->filepath), name);
		evt->path_mode = PATH_MODE_BASENAME;
		return 0;
	}

	return -1;
}

// fill_inode reads the inode number from a dentry.
static __always_inline void fill_inode(struct file_event *evt, struct dentry *dentry) {
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (inode)
		evt->inode = BPF_CORE_READ(inode, i_ino);
}

// ----- security_file_open -----
//
// Prototype: int security_file_open(struct file *file)
//
// Filtering:
//   1. Whitelist PID check
//   2. Skip O_RDONLY opens (flags & O_ACCMODE == 0) — reduces noise ~90%
//      Only capture opens with write intent (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND)

SEC("kprobe/security_file_open")
int BPF_KPROBE(kprobe_security_file_open, struct file *file) {
	// Degradation level 1+: skip file_open (low-risk, high-volume)
	if (get_degrade_level() >= 1)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = BPF_CORE_READ(task, tgid);

	if (is_whitelisted(&file_whitelist_pids, tgid))
		return 0;

	// Read open flags and filter O_RDONLY
	unsigned int f_flags = BPF_CORE_READ(file, f_flags);

	// O_RDONLY = 0, so (flags & O_ACCMODE) == 0 means read-only.
	// Also capture O_CREAT, O_TRUNC, O_APPEND even if combined with O_RDONLY.
	// O_CREAT=0100, O_TRUNC=01000, O_APPEND=02000
	if ((f_flags & 3) == 0 && !(f_flags & (0100 | 01000 | 02000)))
		return 0;

	struct file_event *evt = get_file_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_FILE_OPEN;
	evt->open_flags = f_flags;
	fill_task_info(evt, task);

	// Extract path from file->f_path.dentry
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return 0;

	fill_dentry_path(evt, dentry);
	fill_inode(evt, dentry);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}

// ----- security_inode_rename -----
//
// Prototype: int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
//                                      struct inode *new_dir, struct dentry *new_dentry,
//                                      unsigned int flags)
//
// Captures both old and new paths. No additional filtering — all renames are interesting.

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(kprobe_security_inode_rename,
	struct inode *old_dir, struct dentry *old_dentry,
	struct inode *new_dir, struct dentry *new_dentry) {

	// Degradation level 2+: skip all file events
	if (get_degrade_level() >= 2)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = BPF_CORE_READ(task, tgid);

	if (is_whitelisted(&file_whitelist_pids, tgid))
		return 0;

	struct file_event *evt = get_file_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_FILE_RENAME;
	fill_task_info(evt, task);

	// Old path → filepath
	if (old_dentry) {
		walk_dentry(old_dentry, evt->filepath);
		fill_inode(evt, old_dentry);
	}

	// New path → filepath2
	if (new_dentry)
		walk_dentry(new_dentry, evt->filepath2);

	// Set path_mode based on old path result
	evt->path_mode = PATH_MODE_DENTRY_WALK;

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}

// ----- security_inode_unlink -----
//
// Prototype: int security_inode_unlink(struct inode *dir, struct dentry *dentry)
//
// All unlinks are interesting for EDR — captures file deletion.

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(kprobe_security_inode_unlink, struct inode *dir, struct dentry *dentry) {
	// Degradation level 2+: skip all file events
	if (get_degrade_level() >= 2)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = BPF_CORE_READ(task, tgid);

	if (is_whitelisted(&file_whitelist_pids, tgid))
		return 0;

	if (!dentry)
		return 0;

	struct file_event *evt = get_file_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_FILE_UNLINK;
	fill_task_info(evt, task);
	fill_dentry_path(evt, dentry);
	fill_inode(evt, dentry);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}

// ----- security_inode_setattr -----
//
// Prototype on Rocky 9.7 (kernel 5.14 with RHEL backports):
//   int security_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
//
// Note: upstream kernel < 6.0 uses (struct dentry *, struct iattr *) without idmap.
// Rocky 9 / RHEL 9 backported the idmap parameter from 6.x.
// If targeting vanilla 5.x kernels, remove the idmap parameter.
//
// Filtering: only emit events when ATTR_MODE, ATTR_UID, or ATTR_GID is set.
// This filters out timestamp-only updates (atime/mtime/ctime), size changes, etc.

SEC("kprobe/security_inode_setattr")
int BPF_KPROBE(kprobe_security_inode_setattr, void *idmap, struct dentry *dentry, struct iattr *attr) {
	// Degradation level 2+: skip all file events
	if (get_degrade_level() >= 2)
		return 0;

	if (!dentry || !attr)
		return 0;

	// Read ia_valid flags to determine what's being changed
	unsigned int ia_valid = BPF_CORE_READ(attr, ia_valid);

	// Only interested in permission/ownership changes
	if (!(ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)))
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = BPF_CORE_READ(task, tgid);

	if (is_whitelisted(&file_whitelist_pids, tgid))
		return 0;

	struct file_event *evt = get_file_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_FILE_CHMOD;
	fill_task_info(evt, task);
	fill_dentry_path(evt, dentry);
	fill_inode(evt, dentry);

	// Read new permission mode if ATTR_MODE is set
	if (ia_valid & ATTR_MODE)
		evt->new_mode = BPF_CORE_READ(attr, ia_mode);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}
