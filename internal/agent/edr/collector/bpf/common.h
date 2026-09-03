// common.h — Shared constants, event structures, and helpers between BPF programs.
//
// The Go side reads event structs from perf buffers. Field order, sizes,
// and padding MUST stay in sync with the Go counterparts in ebpf.go.

#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// ----- Constants -----

#define TASK_COMM_LEN     16
#define MAX_FILENAME      256
#define MAX_CMDLINE       512
#define MAX_FILEPATH      256
#define MAX_DENTRY_DEPTH  8     // levels of dentry walk for path reconstruction
#define DENTRY_SLOT_SIZE  32    // bytes per dentry slot (31 name + 1 delimiter)
#define PATH_DELIM        '\xff' // separator between dentry components in BPF output

// ----- Process event types -----

#define EVENT_PROCESS_EXEC  1
#define EVENT_PROCESS_EXIT  2

// ----- File event types -----

#define EVENT_FILE_OPEN     10
#define EVENT_FILE_RENAME   11
#define EVENT_FILE_UNLINK   12
#define EVENT_FILE_CHMOD    13   // also covers chown (ATTR_UID/ATTR_GID)

// File event path_mode values (how the filepath was obtained)
#define PATH_MODE_DENTRY_WALK  0  // partial path from dentry walk (up to 8 levels)
#define PATH_MODE_BASENAME     1  // only filename (d_name.name), no parent

// Attribute flags from linux/fs.h (used by security_inode_setattr)
#define ATTR_MODE  (1 << 0)
#define ATTR_UID   (1 << 1)
#define ATTR_GID   (1 << 2)

// ----- Network event types -----

#define EVENT_NET_TCP_CONNECT  20
#define EVENT_NET_TCP_ACCEPT   21
#define EVENT_NET_UDP_SEND     22

// IP address constants
#define ADDR_SIZE_V6  16   // IPv6 address size; IPv4 uses first 4 bytes

// ----- Event structures -----

// process_event — emitted for exec and exit events.
struct process_event {
	__u8   event_type;
	__u8   _pad[3];
	__u32  pid;
	__u32  tgid;
	__u32  ppid;
	__u32  uid;
	__u32  gid;
	__s32  exit_code;
	__u64  start_ts;
	__u8   in_container;
	__u8   _pad2[7];
	char   comm[TASK_COMM_LEN];
	char   filename[MAX_FILENAME];
	char   cmdline[MAX_CMDLINE];
};

// file_event — emitted for file open/rename/unlink/chmod events.
struct file_event {
	__u8   event_type;          // EVENT_FILE_OPEN / RENAME / UNLINK / CHMOD
	__u8   path_mode;           // PATH_MODE_DENTRY_WALK or PATH_MODE_BASENAME
	__u8   _pad[2];
	__u32  pid;
	__u32  tgid;
	__u32  ppid;
	__u32  uid;
	__u32  gid;
	__u64  inode;               // file inode number (stable across renames)
	__u32  open_flags;          // file_open: raw open flags (O_WRONLY etc)
	__u32  new_mode;            // file_chmod: new permission bits
	__u64  start_ts;
	__u8   in_container;
	__u8   _pad2[7];
	char   comm[TASK_COMM_LEN];
	char   filepath[MAX_FILEPATH];   // primary path (dentry components, \xff separated)
	char   filepath2[MAX_FILEPATH];  // rename: new path; others: unused
};

// network_event — emitted for tcp_connect/tcp_accept/udp_send events.
struct network_event {
	__u8   event_type;          // EVENT_NET_TCP_CONNECT / ACCEPT / UDP_SEND
	__u8   ip_version;          // 4 or 6
	__u8   protocol;            // 6=TCP, 17=UDP (IPPROTO_*)
	__u8   direction;           // 0=outbound, 1=inbound
	__u32  pid;
	__u32  tgid;
	__u32  ppid;
	__u32  uid;
	__u32  gid;
	__u64  start_ts;
	__u8   in_container;
	__u8   _pad[3];
	__u32  local_port;          // host byte order
	__u32  remote_port;         // host byte order
	__u8   local_addr[ADDR_SIZE_V6];   // IPv4: first 4 bytes; IPv6: all 16
	__u8   remote_addr[ADDR_SIZE_V6];
	char   comm[TASK_COMM_LEN];
};

// ----- Shared helpers -----

// Check if a tgid is whitelisted. Returns 1 if whitelisted (should skip).
// Each BPF object defines its own whitelist_pids map; this helper reads from it.
// The map must be defined in the including .c file.
static __always_inline int is_whitelisted(void *map, __u32 tgid) {
	return bpf_map_lookup_elem(map, &tgid) != NULL;
}

// detect_container checks if the task is in a non-root PID namespace.
static __always_inline __u8 detect_container(struct task_struct *task) {
	struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
	if (!ns)
		return 0;

	struct pid_namespace *pid_ns = BPF_CORE_READ(ns, pid_ns_for_children);
	if (!pid_ns)
		return 0;

	unsigned int level = BPF_CORE_READ(pid_ns, level);
	return level > 0 ? 1 : 0;
}

// fill_net_task_info populates common task fields on a network_event.
static __always_inline void fill_net_task_info(struct network_event *evt, struct task_struct *task) {
	evt->pid  = BPF_CORE_READ(task, pid);
	evt->tgid = BPF_CORE_READ(task, tgid);
	evt->uid  = BPF_CORE_READ(task, real_cred, uid.val);
	evt->gid  = BPF_CORE_READ(task, real_cred, gid.val);
	evt->start_ts = bpf_ktime_get_ns();
	evt->in_container = detect_container(task);

	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		evt->ppid = BPF_CORE_READ(parent, tgid);

	BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);
}

// fill_task_info populates common task fields on a file_event.
static __always_inline void fill_task_info(struct file_event *evt, struct task_struct *task) {
	evt->pid  = BPF_CORE_READ(task, pid);
	evt->tgid = BPF_CORE_READ(task, tgid);
	evt->uid  = BPF_CORE_READ(task, real_cred, uid.val);
	evt->gid  = BPF_CORE_READ(task, real_cred, gid.val);
	evt->start_ts = bpf_ktime_get_ns();
	evt->in_container = detect_container(task);

	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (parent)
		evt->ppid = BPF_CORE_READ(parent, tgid);

	BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);
}

// walk_dentry reads dentry names into buf using fixed-size slots.
//
// Fixed-slot layout (BPF verifier safe — all offsets are compile-time constants):
//   buf = [slot0: 32 bytes][slot1: 32 bytes]...[slot7: 32 bytes]
//   Each slot: [name: NUL-terminated, up to 31 bytes][delimiter: \xff at byte 31]
//   Empty slot (name[0] == NUL) marks the end.
//   8 slots * 32 bytes = 256 bytes = MAX_FILEPATH.
//
// Output order: slot0 = filename, slot1 = parent_dir, slot2 = grandparent, ...
// Go side: read each 32-byte slot, skip empty ones, reverse, join with '/'.
//
// Returns number of slots written (0 if nothing was read).
static __always_inline int walk_dentry(struct dentry *dentry, char *buf) {
	struct dentry *d = dentry;
	int count = 0;

	#pragma unroll
	for (int i = 0; i < MAX_DENTRY_DEPTH; i++) {
		if (!d)
			break;

		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (parent == d)
			break;

		const unsigned char *name = BPF_CORE_READ(d, d_name.name);
		if (!name)
			break;

		// All offsets are compile-time constants (i is unrolled).
		// bpf_probe_read_kernel_str NUL-terminates the output.
		bpf_probe_read_kernel_str(&buf[i * DENTRY_SLOT_SIZE], DENTRY_SLOT_SIZE - 1, name);
		buf[i * DENTRY_SLOT_SIZE + DENTRY_SLOT_SIZE - 1] = PATH_DELIM;

		count = i + 1;
		d = parent;
	}

	return count;
}

#endif /* __COMMON_H__ */
