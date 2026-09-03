// Package bde implements the Behavior Detection Engine (BDE) profiler.
// It aggregates EDR events into 4-dimensional behavior profiles (process, file,
// network, DNS) and periodically publishes snapshots to the Server for baseline
// comparison and anomaly detection.
package bde

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// DataTypeBDE is the transport DataType for behavior profile snapshots.
	DataTypeBDE int32 = 3010

	// SnapshotInterval controls how often a profile snapshot is published.
	SnapshotInterval = 60 * time.Second

	// windowDuration is the sliding window for rate calculations.
	windowDuration = 5 * time.Minute
)

// Snapshot is a point-in-time behavior profile for a single host.
// Serialized as map[string]string for gRPC transport.
type Snapshot struct {
	Timestamp int64 `json:"ts"`

	// Process dimension.
	ProcExecCount int     `json:"proc_exec_count"` // total execs in window
	ProcUniqueExe int     `json:"proc_unique_exe"` // distinct exe paths
	ProcForkRate  float64 `json:"proc_fork_rate"`  // execs per second (window avg)

	// File dimension.
	FileWriteCount    int `json:"file_write_count"`    // file write events
	FileUniquePath    int `json:"file_unique_path"`    // distinct file paths
	FileSensitiveHits int `json:"file_sensitive_hits"` // access to sensitive paths

	// Network dimension.
	NetConnectCount  int     `json:"net_connect_count"`  // outbound connections
	NetUniqueIP      int     `json:"net_unique_ip"`      // distinct remote IPs
	NetUniquePort    int     `json:"net_unique_port"`    // distinct remote ports
	NetExternalRatio float64 `json:"net_external_ratio"` // external IP ratio

	// DNS dimension.
	DNSQueryCount   int     `json:"dns_query_count"`   // DNS queries
	DNSUniqueDomain int     `json:"dns_unique_domain"` // distinct domains
	DNSNXRatio      float64 `json:"dns_nx_ratio"`      // NXDOMAIN ratio
}

// Profiler aggregates EDR events into behavior profiles.
type Profiler struct {
	mu     sync.Mutex
	logger *zap.Logger

	// Sliding window event stores.
	procExecs     []time.Time
	procExeSet    map[string]struct{}
	fileWrites    int
	filePathSet   map[string]struct{}
	fileSensitive int
	netConnects   int
	netIPSet      map[string]struct{}
	netPortSet    map[string]struct{}
	netExternal   int
	netTotal      int
	dnsQueries    int
	dnsDomainSet  map[string]struct{}
	dnsNX         int
	dnsTotal      int

	windowStart time.Time
}

// NewProfiler creates a behavior profiler.
func NewProfiler(logger *zap.Logger) *Profiler {
	return &Profiler{
		logger:       logger,
		procExeSet:   make(map[string]struct{}),
		filePathSet:  make(map[string]struct{}),
		netIPSet:     make(map[string]struct{}),
		netPortSet:   make(map[string]struct{}),
		dnsDomainSet: make(map[string]struct{}),
		windowStart:  time.Now(),
	}
}

// ObserveProcessExec records a process execution event.
func (p *Profiler) ObserveProcessExec(exe string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.procExecs = append(p.procExecs, time.Now())
	p.procExeSet[exe] = struct{}{}
}

// ObserveFileWrite records a file write event.
func (p *Profiler) ObserveFileWrite(path string, sensitive bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fileWrites++
	p.filePathSet[path] = struct{}{}
	if sensitive {
		p.fileSensitive++
	}
}

// ObserveNetConnect records an outbound network connection.
func (p *Profiler) ObserveNetConnect(remoteIP, remotePort string, isExternal bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.netConnects++
	p.netIPSet[remoteIP] = struct{}{}
	p.netPortSet[remotePort] = struct{}{}
	p.netTotal++
	if isExternal {
		p.netExternal++
	}
}

// ObserveDNSQuery records a DNS query.
func (p *Profiler) ObserveDNSQuery(domain string, isNXDomain bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dnsQueries++
	p.dnsDomainSet[domain] = struct{}{}
	p.dnsTotal++
	if isNXDomain {
		p.dnsNX++
	}
}

// TakeSnapshot computes and returns the current behavior snapshot, then resets counters.
func (p *Profiler) TakeSnapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(p.windowStart).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}

	// Trim stale process exec timestamps outside window.
	cutoff := now.Add(-windowDuration)
	validExecs := 0
	for _, t := range p.procExecs {
		if t.After(cutoff) {
			validExecs++
		}
	}

	var netExtRatio float64
	if p.netTotal > 0 {
		netExtRatio = float64(p.netExternal) / float64(p.netTotal)
	}

	var dnsNXRatio float64
	if p.dnsTotal > 0 {
		dnsNXRatio = float64(p.dnsNX) / float64(p.dnsTotal)
	}

	snap := Snapshot{
		Timestamp:         now.UnixMilli(),
		ProcExecCount:     validExecs,
		ProcUniqueExe:     len(p.procExeSet),
		ProcForkRate:      float64(validExecs) / elapsed,
		FileWriteCount:    p.fileWrites,
		FileUniquePath:    len(p.filePathSet),
		FileSensitiveHits: p.fileSensitive,
		NetConnectCount:   p.netConnects,
		NetUniqueIP:       len(p.netIPSet),
		NetUniquePort:     len(p.netPortSet),
		NetExternalRatio:  netExtRatio,
		DNSQueryCount:     p.dnsQueries,
		DNSUniqueDomain:   len(p.dnsDomainSet),
		DNSNXRatio:        dnsNXRatio,
	}

	// Reset for next window.
	p.procExecs = p.procExecs[:0]
	p.procExeSet = make(map[string]struct{})
	p.fileWrites = 0
	p.filePathSet = make(map[string]struct{})
	p.fileSensitive = 0
	p.netConnects = 0
	p.netIPSet = make(map[string]struct{})
	p.netPortSet = make(map[string]struct{})
	p.netExternal = 0
	p.netTotal = 0
	p.dnsQueries = 0
	p.dnsDomainSet = make(map[string]struct{})
	p.dnsNX = 0
	p.dnsTotal = 0
	p.windowStart = now

	return snap
}

// SnapshotToFields converts a Snapshot to transport-friendly map[string]string.
func SnapshotToFields(s Snapshot) map[string]string {
	return map[string]string{
		"ts":                  formatInt64(s.Timestamp),
		"proc_exec_count":     formatInt(s.ProcExecCount),
		"proc_unique_exe":     formatInt(s.ProcUniqueExe),
		"proc_fork_rate":      formatFloat(s.ProcForkRate),
		"file_write_count":    formatInt(s.FileWriteCount),
		"file_unique_path":    formatInt(s.FileUniquePath),
		"file_sensitive_hits": formatInt(s.FileSensitiveHits),
		"net_connect_count":   formatInt(s.NetConnectCount),
		"net_unique_ip":       formatInt(s.NetUniqueIP),
		"net_unique_port":     formatInt(s.NetUniquePort),
		"net_external_ratio":  formatFloat(s.NetExternalRatio),
		"dns_query_count":     formatInt(s.DNSQueryCount),
		"dns_unique_domain":   formatInt(s.DNSUniqueDomain),
		"dns_nx_ratio":        formatFloat(s.DNSNXRatio),
	}
}

// IsSensitivePath returns true if the file path is considered sensitive.
func IsSensitivePath(path string) bool {
	for _, prefix := range sensitivePrefixes {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

var sensitivePrefixes = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/etc/ssh/",
	"/etc/crontab",
	"/etc/cron.",
	"/root/",
	"/var/spool/cron/",
	"/etc/ld.so.preload",
	"/etc/pam.d/",
}
