//go:build !linux

package id

func rootFSUUID() string { return "" }
