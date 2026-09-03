//go:build linux

package collector

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"go.uber.org/zap"
)

// HookType describes the BPF attach mechanism used by the collector.
type HookType string

const (
	HookFentry HookType = "fentry" // BPF trampoline (kernel >= 5.5), lower overhead
	HookKprobe HookType = "kprobe" // int3 breakpoint (kernel >= 5.4), universal fallback
)

// detectHookType probes which BPF attach mechanism is available on the running kernel.
//
// Priority:
//  1. fentry/fexit (BPF_PROG_TYPE_TRACING, kernel >= 5.5) — 5-10x lower overhead
//  2. kprobe (kernel >= 5.4) — universal fallback, current default for all hooks
//
// Note: this only detects capability. Actual fentry attach is deferred to Phase 2.
// All hooks currently use kprobe regardless of detection result.
func detectHookType(logger *zap.Logger) HookType {
	// Check if kernel supports BPF_PROG_TYPE_TRACING (fentry/fexit)
	err := features.HaveProgramType(ebpf.Tracing)
	if err != nil {
		logger.Info("fentry not available, using kprobe",
			zap.Error(err),
		)
		return HookKprobe
	}

	logger.Info("fentry support detected (BPF_PROG_TYPE_TRACING available)",
		zap.String("current_hook", "kprobe"),
		zap.String("note", "fentry attach deferred to Phase 2"),
	)
	return HookFentry
}
