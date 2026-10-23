//go:build !linux

package rootkit

import "errors"

type DKOMResult struct {
	HiddenPIDs       []int
	HiddenModules    []string
	HiddenPorts      []int
	PreloadAnomalies []string
	ProcDirMismatch  int
	Warnings         []string
}

func DetectDKOM() (*DKOMResult, error) {
	return nil, errors.New("dkom: linux only")
}
