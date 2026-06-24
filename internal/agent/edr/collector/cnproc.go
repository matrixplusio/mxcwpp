//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

// cn_proc constants from linux/cn_proc.h and linux/connector.h
const (
	netlinkConnector = 11 // NETLINK_CONNECTOR
	cnIDXProc        = 1  // CN_IDX_PROC
	cnVALProc        = 1  // CN_VAL_PROC

	procCNMcastListen = 1 // PROC_CN_MCAST_LISTEN

	procEventExec = 0x00000002 // PROC_EVENT_EXEC
	procEventExit = 0x80000000 // PROC_EVENT_EXIT
)

// cnProcListener listens for process events via the cn_proc netlink connector.
// This provides real-time process exec/exit events on kernels that don't support eBPF.
type cnProcListener struct {
	logger  *zap.Logger
	eventCh chan<- *event.Event
	fd      int
}

// newCNProcListener creates and subscribes to cn_proc events.
func newCNProcListener(logger *zap.Logger, eventCh chan<- *event.Event) (*cnProcListener, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, netlinkConnector)
	if err != nil {
		return nil, fmt.Errorf("create netlink socket: %w", err)
	}

	// Bind to kernel netlink
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: cnIDXProc,
		Pid:    uint32(os.Getpid()),
	}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind netlink: %w", err)
	}

	// Subscribe to proc events
	if err := sendProcCnMcast(fd, procCNMcastListen); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("subscribe cn_proc: %w", err)
	}

	return &cnProcListener{
		logger:  logger,
		eventCh: eventCh,
		fd:      fd,
	}, nil
}

// readLoop reads cn_proc events and emits event.Event until context is cancelled.
func (l *cnProcListener) readLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline to avoid blocking forever
		// Use non-blocking poll via recvfrom with MSG_DONTWAIT
		n, _, err := syscall.Recvfrom(l.fd, buf, syscall.MSG_DONTWAIT)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				// No data available, brief sleep then retry
				// Use a small select to check context and avoid busy loop
				select {
				case <-ctx.Done():
					return
				default:
					syscall.Select(0, nil, nil, nil, &syscall.Timeval{Usec: 50000}) // 50ms
					continue
				}
			}
			l.logger.Warn("cn_proc recvfrom error", zap.Error(err))
			continue
		}

		if n < 52 { // minimum: nlmsghdr(16) + cn_msg header(20) + proc_event header(16)
			continue
		}

		l.parseProcEvent(buf[:n])
	}
}

// parseProcEvent extracts exec/exit events from a netlink cn_proc message.
func (l *cnProcListener) parseProcEvent(data []byte) {
	// Skip nlmsghdr (16 bytes) + cn_msg header (20 bytes) = 36 bytes
	if len(data) < 36+16 {
		return
	}
	payload := data[36:]

	// proc_event: what(u32) + cpu(u32) + timestamp(u64) + event_data
	what := binary.LittleEndian.Uint32(payload[0:4])

	switch what {
	case procEventExec:
		if len(payload) < 24 { // what(4)+cpu(4)+ts(8)+pid(4)+tgid(4)
			return
		}
		pid := int(binary.LittleEndian.Uint32(payload[16:20]))
		tgid := int(binary.LittleEndian.Uint32(payload[20:24]))
		_ = pid // thread pid, we use tgid

		// Supplement from /proc
		exe := readProcExe(tgid)
		cmdline := readProcCmdline(tgid)
		ppid := readProcPPID(tgid)

		evt := event.NewProcessExec(tgid, ppid, exe, cmdline)
		evt.SetField("cwd", readProcCwd(tgid))
		evt.SetField("source", "cn_proc")

		select {
		case l.eventCh <- evt:
		default:
		}

	case procEventExit:
		if len(payload) < 28 { // what(4)+cpu(4)+ts(8)+pid(4)+tgid(4)+exit_code(4)
			return
		}
		tgid := int(binary.LittleEndian.Uint32(payload[20:24]))
		exitCode := int(int32(binary.LittleEndian.Uint32(payload[24:28])))

		evt := event.NewProcessExit(tgid, exitCode)
		evt.SetField("source", "cn_proc")

		select {
		case l.eventCh <- evt:
		default:
		}
	}
}

// close closes the netlink socket.
func (l *cnProcListener) close() {
	syscall.Close(l.fd)
}

// sendProcCnMcast sends a PROC_CN_MCAST_LISTEN/IGNORE message to subscribe/unsubscribe.
func sendProcCnMcast(fd int, op uint32) error {
	// Build: nlmsghdr + cn_msg + op(u32)
	// nlmsghdr: len(4) + type(2) + flags(2) + seq(4) + pid(4) = 16
	// cn_msg:   id.idx(4) + id.val(4) + seq(4) + ack(4) + len(2) + flags(2) = 20
	// op:       4 bytes
	totalLen := 16 + 20 + 4
	buf := make([]byte, totalLen)

	// nlmsghdr
	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint16(buf[4:6], syscall.NLMSG_DONE) // type
	binary.LittleEndian.PutUint16(buf[6:8], 0)                  // flags
	binary.LittleEndian.PutUint32(buf[8:12], 0)                 // seq
	binary.LittleEndian.PutUint32(buf[12:16], uint32(os.Getpid()))

	// cn_msg
	binary.LittleEndian.PutUint32(buf[16:20], cnIDXProc) // id.idx
	binary.LittleEndian.PutUint32(buf[20:24], cnVALProc) // id.val
	binary.LittleEndian.PutUint32(buf[24:28], 0)         // seq
	binary.LittleEndian.PutUint32(buf[28:32], 0)         // ack
	binary.LittleEndian.PutUint16(buf[32:34], 4)         // len (of data)
	binary.LittleEndian.PutUint16(buf[34:36], 0)         // flags

	// operation
	binary.LittleEndian.PutUint32(buf[36:40], op)

	dest := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    0, // kernel
	}
	return syscall.Sendto(fd, buf, 0, dest)
}

// readProcCwd reads /proc/[pid]/cwd symlink (current working directory).
func readProcCwd(pid int) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return path
}

// readProcExe reads /proc/[pid]/exe symlink.
func readProcExe(pid int) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return path
}

// readProcCmdline reads /proc/[pid]/cmdline and converts NUL to space.
func readProcCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	for i := range data {
		if data[i] == 0 {
			data[i] = ' '
		}
	}
	return strings.TrimSpace(string(data))
}

// readProcPPID reads PPID from /proc/[pid]/stat.
func readProcPPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	return parsePPIDFromStat(string(data))
}

// Ensure cnProcListener size is known at compile time to catch struct layout issues.
var _ = unsafe.Sizeof(cnProcListener{})
