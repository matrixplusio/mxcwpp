//go:build linux

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

// fanotify constants not yet in x/sys/unix on all versions.
const (
	fanClassNotif   = 0x00000000 // FAN_CLASS_NOTIF
	fanNonblock     = 0x00000002 // FAN_NONBLOCK
	fanCloseWrite   = 0x00000008 // FAN_CLOSE_WRITE
	fanMarkAdd      = 0x00000001 // FAN_MARK_ADD
	fanMarkMount    = 0x00000010 // FAN_MARK_MOUNT
	fanotifyInitAll = fanClassNotif | fanNonblock
)

// fanotifyEventMetadata mirrors the kernel's fanotify_event_metadata.
type fanotifyEventMetadata struct {
	EventLen    uint32
	Version     uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	Fd          int32
	Pid         int32
}

const fanotifyEventSize = int(unsafe.Sizeof(fanotifyEventMetadata{}))

// fanotifyListener monitors filesystem events via the fanotify API.
// Captures FAN_CLOSE_WRITE on the root mount (files written-then-closed).
type fanotifyListener struct {
	logger  *zap.Logger
	eventCh chan<- *event.Event
	fd      int
}

// newFanotifyListener initialises fanotify and marks the root mount.
func newFanotifyListener(logger *zap.Logger, eventCh chan<- *event.Event) (*fanotifyListener, error) {
	fd, err := unix.FanotifyInit(fanotifyInitAll, uint(os.O_RDONLY|syscall.O_CLOEXEC))
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}

	// Monitor the root mount for close-after-write events.
	if err := unix.FanotifyMark(fd, fanMarkAdd|fanMarkMount, fanCloseWrite, unix.AT_FDCWD, "/"); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("fanotify_mark /: %w", err)
	}

	return &fanotifyListener{
		logger:  logger,
		eventCh: eventCh,
		fd:      fd,
	}, nil
}

// readLoop reads fanotify events until the context is cancelled.
func (l *fanotifyListener) readLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := syscall.Read(l.fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				select {
				case <-ctx.Done():
					return
				default:
					syscall.Select(0, nil, nil, nil, &syscall.Timeval{Usec: 50000}) // 50ms
					continue
				}
			}
			l.logger.Warn("fanotify read error", zap.Error(err))
			continue
		}

		l.parseEvents(buf[:n])
	}
}

// parseEvents decodes one or more fanotify_event_metadata from buf.
func (l *fanotifyListener) parseEvents(data []byte) {
	for len(data) >= fanotifyEventSize {
		var meta fanotifyEventMetadata
		if err := binary.Read(bytes.NewReader(data[:fanotifyEventSize]), binary.LittleEndian, &meta); err != nil {
			break
		}
		if meta.EventLen < uint32(fanotifyEventSize) {
			break
		}

		if meta.Fd >= 0 {
			l.handleEvent(&meta)
			syscall.Close(int(meta.Fd))
		}

		data = data[meta.EventLen:]
	}
}

// handleEvent resolves file path from the event fd and emits a file event.
func (l *fanotifyListener) handleEvent(meta *fanotifyEventMetadata) {
	path := l.fdPath(int(meta.Fd))
	if path == "" {
		return
	}

	pid := int(meta.Pid)

	var evtType event.EventType
	switch {
	case meta.Mask&fanCloseWrite != 0:
		evtType = event.FileWrite
	default:
		return
	}

	evt := event.NewFileEvent(evtType, pid, path)
	evt.SetField("source", "fanotify")

	select {
	case l.eventCh <- evt:
	default:
	}
}

// fdPath resolves /proc/self/fd/<fd> to the actual file path.
func (l *fanotifyListener) fdPath(fd int) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return path
}

// close releases the fanotify file descriptor.
func (l *fanotifyListener) close() {
	syscall.Close(l.fd)
}
