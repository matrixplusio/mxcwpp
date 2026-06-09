package collector

// PrivilegeEvent 与 bpf/privilege.c 内 struct privilege_event 字段对齐。
//
// 改字段顺序/类型必须同步 C 端。
//
// 加载入口 (Linux only, 待 go generate 产生 bindings 后接入):
//
//	loadPrivilegeObjects → kprobe 6 attach → perf reader 读出本 struct
//
// 字段说明:
//
//	EventType    见 bpf/common.h EVENT_PRIV_*
//	OldUID/NewUID commit_creds 时 UID 变更前后
//	OldGID/NewGID 同 GID
//	TargetPID    ptrace 时被注入的目标 PID
//	CapEffective 提权后的 effective cap mask
//	Payload      mount 时 source[0:128] + target[128:256] 或 LKM 名 [0:64]
type PrivilegeEvent struct {
	EventType    uint32
	PID          uint32
	TGID         uint32
	PPID         uint32
	OldUID       uint32
	NewUID       uint32
	OldGID       uint32
	NewGID       uint32
	TargetPID    uint32
	CapEffective uint64
	TimestampNS  uint64
	Comm         [16]byte
	Payload      [256]byte
}

// PrivilegeEvent 类型常量 (mirror bpf/common.h)。
const (
	EventPrivCommitCreds = 30
	EventPrivSetUID      = 31
	EventPrivSetGID      = 32
	EventPrivPtrace      = 33
	EventPrivMount       = 34
	EventPrivKmodLoad    = 35
)
