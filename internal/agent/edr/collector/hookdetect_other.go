//go:build !linux

package collector

// HookType describes the BPF attach mechanism used by the collector.
type HookType string

const (
	HookFentry HookType = "fentry"
	HookKprobe HookType = "kprobe"
)
