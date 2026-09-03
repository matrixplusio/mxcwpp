//go:build !linux

// Stub for non-Linux platforms. Container resolution requires /proc/cgroup
// and container runtime CLI tools only available on Linux.
package container

import "go.uber.org/zap"

// Info holds resolved container metadata.
type Info struct {
	ContainerID string
	Name        string
	Image       string
	Runtime     string
	Labels      map[string]string
	PodName     string
	Namespace   string
	PodUID      string
}

// Resolver is a no-op stub on non-Linux platforms.
type Resolver struct{}

// NewResolver returns a no-op resolver on non-Linux.
func NewResolver(_ *zap.Logger) *Resolver {
	return &Resolver{}
}

// Resolve always returns nil on non-Linux.
func (r *Resolver) Resolve(_ int) *Info { return nil }

// Runtime returns empty string on non-Linux.
func (r *Resolver) Runtime() string { return "" }

// Cleanup is a no-op on non-Linux.
func (r *Resolver) Cleanup() int { return 0 }

// Stats returns 0 on non-Linux.
func (r *Resolver) Stats() int { return 0 }
