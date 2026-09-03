//go:build linux

// fid_parser_linux.go — fanotify FID / DFID_NAME / PIDFD 解析 (P5-4 完整实现).
//
// fanotify_event_metadata 之后是 0..N 个 info record:
//
//	struct fanotify_event_info_header {
//	    __u8  info_type;
//	    __u8  pad;
//	    __u16 len;
//	};
//
// 紧跟具体 type:
//
//	FAN_EVENT_INFO_TYPE_FID / DFID / DFID_NAME:
//	    struct fanotify_event_info_fid {
//	        struct fanotify_event_info_header hdr;
//	        __kernel_fsid_t  fsid;       // 8 bytes
//	        unsigned char    handle[];   // = file_handle {handle_bytes, handle_type, f_handle[]}
//	    };
//	    DFID_NAME 末尾还有 nul-terminated name (子文件名).
//
//	FAN_EVENT_INFO_TYPE_PIDFD:
//	    struct fanotify_event_info_pidfd {
//	        struct fanotify_event_info_header hdr;
//	        __s32  pidfd;
//	    };
package fanotify

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// info_type 常量 (与 <linux/fanotify.h> 一致).
const (
	FAN_EVENT_INFO_TYPE_FID       = 1
	FAN_EVENT_INFO_TYPE_DFID_NAME = 2
	FAN_EVENT_INFO_TYPE_DFID      = 3
	FAN_EVENT_INFO_TYPE_PIDFD     = 4
	FAN_EVENT_INFO_TYPE_ERROR     = 5
)

// infoRecord 一条 info_type+len 头解析结果.
type infoRecord struct {
	Type uint8
	Len  uint16
	Body []byte
}

// iterInfoRecords 遍历 metadata 之后的 info records.
func iterInfoRecords(meta *unix.FanotifyEventMetadata, payload []byte) []infoRecord {
	metaSize := int(unsafe.Sizeof(*meta))
	totalLen := int(meta.Event_len)
	if metaSize >= totalLen || metaSize >= len(payload) {
		return nil
	}
	rest := payload[metaSize:totalLen]
	var out []infoRecord
	for len(rest) >= 4 {
		typ := rest[0]
		l := binary.LittleEndian.Uint16(rest[2:4])
		if int(l) > len(rest) || l < 4 {
			break
		}
		out = append(out, infoRecord{Type: typ, Len: l, Body: rest[4:l]})
		rest = rest[l:]
	}
	return out
}

// parsePidfd 从 PIDFD 记录里取 fd.
func parsePidfd(rec infoRecord) int32 {
	if rec.Type != FAN_EVENT_INFO_TYPE_PIDFD || len(rec.Body) < 4 {
		return -1
	}
	return int32(binary.LittleEndian.Uint32(rec.Body[:4]))
}

// parseFIDName 解析 DFID_NAME 的 file_handle + 末尾 name.
//
//	body 布局: [__kernel_fsid_t fsid (8)] [file_handle {bytes(4), type(4), handle[]}] [name\0]
//
// 返回 mount-relative path 重建用的 fsid + handle + name.
// 调用 open_by_handle_at 的部分留到 NewWatcher loop 里 (需要 mount_fd).
type fidNameParsed struct {
	FsID   [8]byte
	Handle []byte
	HType  int32
	HBytes int32
	Name   string
}

func parseFIDName(rec infoRecord) (*fidNameParsed, bool) {
	if rec.Type != FAN_EVENT_INFO_TYPE_DFID_NAME &&
		rec.Type != FAN_EVENT_INFO_TYPE_FID &&
		rec.Type != FAN_EVENT_INFO_TYPE_DFID {
		return nil, false
	}
	if len(rec.Body) < 8+8 {
		return nil, false
	}
	out := &fidNameParsed{}
	copy(out.FsID[:], rec.Body[:8])
	hb := int32(binary.LittleEndian.Uint32(rec.Body[8:12]))
	ht := int32(binary.LittleEndian.Uint32(rec.Body[12:16]))
	out.HBytes = hb
	out.HType = ht
	if int(hb) <= 0 || 16+int(hb) > len(rec.Body) {
		return nil, false
	}
	out.Handle = make([]byte, hb)
	copy(out.Handle, rec.Body[16:16+hb])
	if rec.Type == FAN_EVENT_INFO_TYPE_DFID_NAME {
		tail := rec.Body[16+hb:]
		nullIdx := -1
		for i, b := range tail {
			if b == 0 {
				nullIdx = i
				break
			}
		}
		if nullIdx > 0 {
			out.Name = string(tail[:nullIdx])
		}
	}
	return out, true
}

// resolveByHandle 用 open_by_handle_at 把 file_handle 解析回文件描述符 + 路径.
//
// mountFd 必须是 watch 时存好的某个挂载点 fd; 此处用 AT_FDCWD 退化, 实际生产应
// 在 WatchFilesystem 时 keep mount fd 表.
func resolveByHandle(parsed *fidNameParsed, mountFd int) (string, error) {
	if parsed == nil || len(parsed.Handle) == 0 {
		return "", fmt.Errorf("empty handle")
	}
	// 构造 unix.FileHandle 结构 (handle_bytes + handle_type + f_handle[]).
	fh := unix.NewFileHandle(int32(parsed.HType), parsed.Handle)
	if mountFd <= 0 {
		mountFd = unix.AT_FDCWD
	}
	fd, err := unix.OpenByHandleAt(mountFd, fh, unix.O_RDONLY|unix.O_PATH|unix.O_NONBLOCK)
	if err != nil {
		return "", fmt.Errorf("open_by_handle_at: %w", err)
	}
	defer unix.Close(fd)
	link := fmt.Sprintf("/proc/self/fd/%d", fd)
	target, err := os.Readlink(link)
	if err != nil {
		return "", err
	}
	if parsed.Name != "" {
		return filepath.Join(target, parsed.Name), nil
	}
	return target, nil
}

// resolvePidfd /proc/self/fdinfo/<pidfd> 里 Pid 字段 → 真实 PID.
// 比 meta.Pid 更可靠 (后者在 reaper 后会被回收).
func resolvePidfd(pidfd int32) int32 {
	if pidfd < 0 {
		return -1
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil {
		return -1
	}
	// 查 Pid:\tNNN
	const key = "Pid:"
	idx := -1
	for i := 0; i+len(key) < len(data); i++ {
		if string(data[i:i+len(key)]) == key {
			idx = i + len(key)
			break
		}
	}
	if idx < 0 {
		return -1
	}
	for idx < len(data) && (data[idx] == '\t' || data[idx] == ' ') {
		idx++
	}
	start := idx
	for idx < len(data) && data[idx] >= '0' && data[idx] <= '9' {
		idx++
	}
	if idx == start {
		return -1
	}
	var n int32
	for i := start; i < idx; i++ {
		n = n*10 + int32(data[i]-'0')
	}
	return n
}
