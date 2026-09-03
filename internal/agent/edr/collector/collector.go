//go:build linux

// Package collector defines the interface and mode detection for EDR event collectors.
//
// Two modes are supported:
//   - eBPF mode (kernel >= 5.4): high-performance kernel-level event collection
//   - Userspace mode (fallback): cn_proc + fanotify + /proc/net polling
//
// The factory function DetectAndCreate automatically probes the running kernel
// and returns the best available collector.
package collector

import (
	"context"
	"fmt"
	"os"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

// Mode represents the event collection mode.
type Mode string

const (
	ModeEBPF      Mode = "ebpf"      // kernel >= 5.4, full capabilities
	ModeUserspace Mode = "userspace" // fallback for old kernels
)

// Capability flags declare what a collector can do.
// Used by the rule engine to disable rules that require unavailable capabilities.
type Capability string

const (
	CapEBPFFull     Capability = "ebpf_full"
	CapFileFull     Capability = "file_full"     // rename/unlink/chmod (eBPF only)
	CapNetworkFull  Capability = "network_full"  // tcp_connect/accept/udp_send (eBPF only)
	CapDNSFull      Capability = "dns_full"      // DNS query capture
	CapContainerCtx Capability = "container_ctx" // container context injection

	// Userspace fallback capabilities (reduced feature set).
	CapProcessBasic Capability = "process_basic" // cn_proc exec/exit only
	CapFileBasic    Capability = "file_basic"    // fanotify close_write only
	CapNetworkBasic Capability = "network_basic" // /proc/net polling (no short-lived conns)
)

// Collector is the interface that all event collectors must implement.
type Collector interface {
	// Mode returns the collector's operating mode.
	Mode() Mode

	// Capabilities returns the set of capabilities this collector provides.
	Capabilities() []Capability

	// HookType returns the BPF attach mechanism detected/used (fentry or kprobe).
	HookType() HookType

	// Start begins event collection. Events are sent to the returned channel.
	// The channel is closed when the collector stops or the context is cancelled.
	Start(ctx context.Context) (<-chan *event.Event, error)

	// Stop gracefully shuts down the collector and releases resources.
	Stop() error

	// DegradationLevel returns the current dynamic degradation level (0-3).
	DegradationLevel() int32
}

// DetectAndCreate probes the running kernel and returns the best available collector.
// It tries eBPF first; if that fails (old kernel, missing caps), falls back to userspace.
func DetectAndCreate(logger *zap.Logger) (Collector, error) {
	if ebpfAvailable(logger) {
		logger.Info("eBPF support detected, using eBPF collector")
		return newEBPFCollector(logger)
	}

	logger.Info("eBPF not available, falling back to userspace collector")
	return newUserspaceCollector(logger)
}

// ebpfAvailable checks whether the running kernel supports the eBPF features we need.
func ebpfAvailable(logger *zap.Logger) bool {
	major, minor, err := kernelVersion()
	if err != nil {
		logger.Warn("failed to detect kernel version, assuming no eBPF", zap.Error(err))
		return false
	}

	logger.Debug("kernel version detected", zap.Int("major", major), zap.Int("minor", minor))

	// Require kernel >= 5.4 for BPF CO-RE / trampoline support
	if major < 5 || (major == 5 && minor < 4) {
		logger.Info("kernel too old for eBPF",
			zap.Int("major", major), zap.Int("minor", minor),
			zap.String("required", ">=5.4"))
		return false
	}

	// TODO (Phase 1.2+): probe BPF program types, try loading a minimal BPF program
	return true
}

// kernelVersion parses the running kernel's major.minor version.
func kernelVersion() (major, minor int, err error) {
	data, readErr := os.ReadFile("/proc/version")
	if readErr != nil {
		return 0, 0, readErr
	}
	// Format: "Linux version X.Y.Z-..."
	n, scanErr := fmt.Sscanf(string(data), "Linux version %d.%d", &major, &minor)
	if scanErr != nil || n < 2 {
		return 0, 0, fmt.Errorf("failed to parse kernel version from: %s", string(data))
	}
	return major, minor, nil
}
