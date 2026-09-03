// network.c — BPF programs for network event collection.
//
// Hooks (kprobe/kretprobe):
//   tcp_connect          — outbound TCP connection initiation
//   inet_csk_accept      — inbound TCP connection accepted (kretprobe)
//   udp_sendmsg          — outbound UDP datagram send
//
// IPv4/IPv6: reads sock_common fields. IPv4 uses 4-byte addresses stored in
// the first 4 bytes of the 16-byte addr arrays. IPv6 uses all 16 bytes.
//
// Filtering:
//   1. Whitelist PID check (BPF Map)
//   2. Skip loopback addresses (127.0.0.0/8 for v4, ::1 for v6)

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ----- Maps (network-specific) -----

// Perf buffer for delivering network events to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} net_events SEC(".maps");

// Per-CPU scratch buffer for building network_event.
// network_event is 92 bytes (fits 512B stack limit), but using scratch
// for consistency with process/file collectors and future-proofing.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct network_event);
} net_event_scratch SEC(".maps");

// PIDs to skip (agent self, child plugins). Populated from Go side.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} net_whitelist_pids SEC(".maps");

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

// get_net_event_buf returns a zeroed network_event from the per-CPU scratch buffer.
static __always_inline struct network_event *get_net_event_buf(void) {
	__u32 zero = 0;
	struct network_event *evt = bpf_map_lookup_elem(&net_event_scratch, &zero);
	if (!evt)
		return 0;

	// Zero all scalar fields
	evt->event_type = 0;
	evt->ip_version = 0;
	evt->protocol = 0;
	evt->direction = 0;
	evt->pid = 0;
	evt->tgid = 0;
	evt->ppid = 0;
	evt->uid = 0;
	evt->gid = 0;
	evt->start_ts = 0;
	evt->in_container = 0;
	evt->_pad[0] = 0; evt->_pad[1] = 0; evt->_pad[2] = 0;
	evt->local_port = 0;
	evt->remote_port = 0;

	// Zero address arrays — fixed 16 bytes each, safe for memset.
	__builtin_memset(evt->local_addr, 0, ADDR_SIZE_V6);
	__builtin_memset(evt->remote_addr, 0, ADDR_SIZE_V6);

	// Zero comm
	evt->comm[0] = '\0';

	return evt;
}

// is_loopback_v4 checks if an IPv4 address is loopback (127.0.0.0/8).
static __always_inline int is_loopback_v4(__u32 addr) {
	// addr is in network byte order; 127.x.x.x → first byte is 0x7f
	return (addr & 0xFF) == 0x7F;
}

// is_loopback_v6 checks if an IPv6 address is ::1.
static __always_inline int is_loopback_v6(const __u8 *addr) {
	// ::1 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
	#pragma unroll
	for (int i = 0; i < 15; i++) {
		if (addr[i] != 0)
			return 0;
	}
	return addr[15] == 1;
}

// fill_sock_addrs reads address and port info from a sock's sock_common.
// Returns 0 on success, -1 if address family is unsupported or loopback.
static __always_inline int fill_sock_addrs(struct network_event *evt, struct sock *sk) {
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family == 2) { // AF_INET
		evt->ip_version = 4;

		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

		if (is_loopback_v4(daddr) || is_loopback_v4(saddr))
			return -1;

		// Store IPv4 in first 4 bytes of addr arrays (network byte order)
		__builtin_memcpy(evt->remote_addr, &daddr, 4);
		__builtin_memcpy(evt->local_addr, &saddr, 4);

	} else if (family == 10) { // AF_INET6
		evt->ip_version = 6;

		// Read IPv6 addresses via BPF_CORE_READ into local buffers
		struct in6_addr daddr6, saddr6;
		BPF_CORE_READ_INTO(&daddr6, sk, __sk_common.skc_v6_daddr);
		BPF_CORE_READ_INTO(&saddr6, sk, __sk_common.skc_v6_rcv_saddr);

		if (is_loopback_v6(daddr6.in6_u.u6_addr8) || is_loopback_v6(saddr6.in6_u.u6_addr8))
			return -1;

		__builtin_memcpy(evt->remote_addr, &daddr6, ADDR_SIZE_V6);
		__builtin_memcpy(evt->local_addr, &saddr6, ADDR_SIZE_V6);

	} else {
		return -1; // unsupported address family
	}

	// Ports: skc_dport is big-endian, skc_num is host-endian
	evt->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	evt->local_port  = BPF_CORE_READ(sk, __sk_common.skc_num);

	return 0;
}

// ----- tcp_connect -----
//
// Prototype: int tcp_connect(struct sock *sk)
//
// Fires when a TCP SYN is about to be sent. The sock already has
// local/remote addresses and ports populated by the connect() path.

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
	// Degradation level 3+: skip all network events
	if (get_degrade_level() >= 3)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = BPF_CORE_READ(task, tgid);

	if (is_whitelisted(&net_whitelist_pids, tgid))
		return 0;

	struct network_event *evt = get_net_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_NET_TCP_CONNECT;
	evt->protocol = 6; // IPPROTO_TCP
	evt->direction = 0; // outbound
	fill_net_task_info(evt, task);

	if (fill_sock_addrs(evt, sk) < 0)
		return 0; // loopback or unsupported family

	bpf_perf_event_output(ctx, &net_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}

// ----- inet_csk_accept (kretprobe) -----
//
// Prototype: struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern)
//
// Returns the newly accepted socket. We use kretprobe to capture the return value
// which is the child sock with remote client addresses populated.

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, struct sock *newsk) {
	// Degradation level 2+: only tcp_connect, skip tcp_accept
	if (get_degrade_level() >= 2)
		return 0;

	if (!newsk)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = BPF_CORE_READ(task, tgid);

	if (is_whitelisted(&net_whitelist_pids, tgid))
		return 0;

	struct network_event *evt = get_net_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_NET_TCP_ACCEPT;
	evt->protocol = 6; // IPPROTO_TCP
	evt->direction = 1; // inbound
	fill_net_task_info(evt, task);

	if (fill_sock_addrs(evt, newsk) < 0)
		return 0;

	bpf_perf_event_output(ctx, &net_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}

// ----- udp_sendmsg -----
//
// Prototype: int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
//
// Fires for every UDP datagram send. For connected UDP sockets, the destination
// is in sk->__sk_common. For unconnected sendto(), the destination is in
// msg->msg_name (struct sockaddr_in). We read from sk first; if remote_port
// is 0 (unconnected), we try msg->msg_name.

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
	// Degradation level 2+: only tcp_connect, skip udp_send
	if (get_degrade_level() >= 2)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 tgid = BPF_CORE_READ(task, tgid);

	if (is_whitelisted(&net_whitelist_pids, tgid))
		return 0;

	struct network_event *evt = get_net_event_buf();
	if (!evt)
		return 0;

	evt->event_type = EVENT_NET_UDP_SEND;
	evt->protocol = 17; // IPPROTO_UDP
	evt->direction = 0; // outbound
	fill_net_task_info(evt, task);

	// Read family from sock
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family == 2) { // AF_INET
		evt->ip_version = 4;

		// Local address from sock
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(evt->local_addr, &saddr, 4);
		evt->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);

		// Remote: try connected sock first
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

		if (daddr == 0 && msg) {
			// Unconnected UDP: read destination from msg->msg_name (sockaddr_in)
			void *msg_name = BPF_CORE_READ(msg, msg_name);
			if (msg_name) {
				struct sockaddr_in sa = {};
				bpf_probe_read_kernel(&sa, sizeof(sa), msg_name);
				daddr = sa.sin_addr.s_addr;
				dport = sa.sin_port;
			}
		}

		if (is_loopback_v4(daddr))
			return 0;

		__builtin_memcpy(evt->remote_addr, &daddr, 4);
		evt->remote_port = bpf_ntohs(dport);

	} else if (family == 10) { // AF_INET6
		evt->ip_version = 6;

		struct in6_addr saddr6;
		BPF_CORE_READ_INTO(&saddr6, sk, __sk_common.skc_v6_rcv_saddr);
		__builtin_memcpy(evt->local_addr, &saddr6, ADDR_SIZE_V6);
		evt->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);

		struct in6_addr daddr6;
		BPF_CORE_READ_INTO(&daddr6, sk, __sk_common.skc_v6_daddr);
		__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

		// Check if connected (daddr6 all-zero means unconnected)
		int connected = 0;
		#pragma unroll
		for (int i = 0; i < 16; i++) {
			if (daddr6.in6_u.u6_addr8[i] != 0) {
				connected = 1;
				break;
			}
		}

		if (!connected && msg) {
			void *msg_name = BPF_CORE_READ(msg, msg_name);
			if (msg_name) {
				struct sockaddr_in6 sa6 = {};
				bpf_probe_read_kernel(&sa6, sizeof(sa6), msg_name);
				__builtin_memcpy(&daddr6, &sa6.sin6_addr, ADDR_SIZE_V6);
				dport = sa6.sin6_port;
			}
		}

		if (is_loopback_v6(daddr6.in6_u.u6_addr8))
			return 0;

		__builtin_memcpy(evt->remote_addr, &daddr6, ADDR_SIZE_V6);
		evt->remote_port = bpf_ntohs(dport);

	} else {
		return 0; // unsupported family
	}

	bpf_perf_event_output(ctx, &net_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));

	return 0;
}
