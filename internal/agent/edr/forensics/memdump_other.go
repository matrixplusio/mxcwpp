//go:build !linux

package forensics

import (
	"errors"
	"time"

	"go.uber.org/zap"
)

type MemRegion struct {
	Start, End uint64
	Perms      string
	Offset     uint64
	Pathname   string
}

type VolatilityProfile struct {
	KernelVersion string
	OSRelease     string
	Arch          string
	PageSize      int
	HostName      string
	Timestamp     time.Time
}

func DumpProcessMemory(_ int, _ string, _ *zap.Logger) error {
	return errors.New("memdump: linux only (/proc/<pid>/mem)")
}

func DumpFullSystemMemory(_ string, _ *zap.Logger) error {
	return errors.New("memdump: linux only (/proc/kcore)")
}

func CaptureProfile() (*VolatilityProfile, error) {
	return nil, errors.New("forensics: linux only")
}

func WriteForensicsBundle(_ int, _ string, _ *zap.Logger) (string, error) {
	return "", errors.New("forensics: linux only")
}
