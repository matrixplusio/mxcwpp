//go:build !linux

package auth

import "os/exec"

func setChildAttrs(*exec.Cmd) {}

// LowerSelfPriority 非 Linux 平台无操作。
func LowerSelfPriority() error { return nil }

func lowerChildPriority(int) error { return nil }
