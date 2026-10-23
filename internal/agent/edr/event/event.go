// Package event defines unified EDR event types for process, file, and network events.
package event

import (
	"fmt"
	"time"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
)

// DataType constants for EDR events, matching Server consumer expectations.
// Registered in docs/datatype-allocation.md — update that doc before adding new values.
const (
	DataTypeProcess int32 = 3000 // process_exec / process_exit
	DataTypeFile    int32 = 3001 // file_open / file_write / file_rename / file_unlink / file_chmod
	DataTypeNetwork int32 = 3002 // tcp_connect / tcp_accept / tcp_close / udp_send
	DataTypeDNS     int32 = 3003 // dns_query (Phase 6)
	DataTypeBDE     int32 = 3010 // behavior_profile (BDE Phase 10)
	DataTypeMemory  int32 = 3004 // memory threat (memfd/deleted_exe/anonymous_exec, Phase 15)
	DataTypePriv    int32 = 3005 // privilege escalation (M1-1: commit_creds / setuid / ptrace / mount / kmod)
	DataTypeRootkit int32 = 3006 // anti-rootkit integrity report (M1-2: syscall_table / kmod hide / sysfs anomaly)
)

// EventType is the specific event subtype string carried in the "event_type" field.
type EventType string

// Process event types.
const (
	ProcessExec EventType = "process_exec"
	ProcessExit EventType = "process_exit"
)

// File event types.
const (
	FileOpen   EventType = "file_open"
	FileWrite  EventType = "file_write"
	FileRename EventType = "file_rename"
	FileUnlink EventType = "file_unlink"
	FileChmod  EventType = "file_chmod"
)

// Network event types.
const (
	TCPConnect EventType = "tcp_connect"
	TCPAccept  EventType = "tcp_accept"
	TCPClose   EventType = "tcp_close"
	UDPSend    EventType = "udp_send"
)

// DNS event types.
const (
	DNSQuery    EventType = "dns_query"
	DNSResponse EventType = "dns_response"
)

// Signal event types.
const (
	SignalSend EventType = "signal_send"
)

// Memory threat event types (Phase 15).
const (
	MemfdExec     EventType = "memfd_exec"     // process using memfd-backed file descriptor
	DeletedExe    EventType = "deleted_exe"    // process running from deleted executable
	AnonymousExec EventType = "anonymous_exec" // suspicious anonymous rwx memory regions
)

// Event is the unified EDR event structure produced by collectors.
// All event types share a common header; type-specific data goes into Fields.
type Event struct {
	DataType  int32             // 3000 / 3001 / 3002 / 3003
	EventType EventType         // e.g. "process_exec"
	Timestamp time.Time         // event timestamp (kernel or userspace)
	Fields    map[string]string // all event data as string KV (matches bridge.Payload)
}

// NewProcessExec creates a process_exec event with required fields.
func NewProcessExec(pid, ppid int, exe, cmdline string) *Event {
	return &Event{
		DataType:  DataTypeProcess,
		EventType: ProcessExec,
		Timestamp: time.Now(),
		Fields: map[string]string{
			"event_type": string(ProcessExec),
			"pid":        fmt.Sprintf("%d", pid),
			"ppid":       fmt.Sprintf("%d", ppid),
			"exe":        exe,
			"cmdline":    cmdline,
		},
	}
}

// NewProcessExit creates a process_exit event.
func NewProcessExit(pid int, exitCode int) *Event {
	return &Event{
		DataType:  DataTypeProcess,
		EventType: ProcessExit,
		Timestamp: time.Now(),
		Fields: map[string]string{
			"event_type": string(ProcessExit),
			"pid":        fmt.Sprintf("%d", pid),
			"exit_code":  fmt.Sprintf("%d", exitCode),
		},
	}
}

// NewFileEvent creates a file event (open/write/rename/unlink/chmod).
func NewFileEvent(eventType EventType, pid int, filePath string) *Event {
	return &Event{
		DataType:  DataTypeFile,
		EventType: eventType,
		Timestamp: time.Now(),
		Fields: map[string]string{
			"event_type": string(eventType),
			"pid":        fmt.Sprintf("%d", pid),
			"file_path":  filePath,
		},
	}
}

// NewNetworkEvent creates a network event (tcp_connect/tcp_accept/tcp_close/udp_send).
func NewNetworkEvent(eventType EventType, pid int, remoteAddr string, remotePort int, protocol string) *Event {
	return &Event{
		DataType:  DataTypeNetwork,
		EventType: eventType,
		Timestamp: time.Now(),
		Fields: map[string]string{
			"event_type":  string(eventType),
			"pid":         fmt.Sprintf("%d", pid),
			"remote_addr": remoteAddr,
			"remote_port": fmt.Sprintf("%d", remotePort),
			"protocol":    protocol,
		},
	}
}

// SetField sets a field value on the event. Chainable.
func (e *Event) SetField(key, value string) *Event {
	if e.Fields == nil {
		e.Fields = make(map[string]string)
	}
	e.Fields[key] = value
	return e
}

// ToRecord converts an Event to a bridge.Record for transport via gRPC.
func (e *Event) ToRecord() *bridge.Record {
	return &bridge.Record{
		DataType:  e.DataType,
		Timestamp: e.Timestamp.UnixNano(),
		Data: &bridge.Payload{
			Fields: e.Fields,
		},
	}
}
