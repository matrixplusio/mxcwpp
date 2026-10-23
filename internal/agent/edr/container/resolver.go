//go:build linux

// Package container provides container metadata resolution for EDR events.
// It resolves container IDs (from cgroup) to container name, image, labels
// by querying containerd/docker runtime APIs via CLI.
package container

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Info holds resolved container metadata.
type Info struct {
	ContainerID string
	Name        string
	Image       string
	Runtime     string // "docker" / "containerd" / "crio"
	Labels      map[string]string
	// K8s context (populated if running under K8s).
	PodName   string
	Namespace string
	PodUID    string
}

// Resolver resolves container IDs to metadata using runtime CLI tools.
// Results are cached with TTL to avoid excessive CLI calls.
type Resolver struct {
	logger  *zap.Logger
	runtime string // detected runtime: "docker" / "containerd" / ""

	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	info      *Info
	timestamp time.Time
}

const (
	cacheTTL     = 5 * time.Minute
	cacheMaxSize = 2000
	cmdTimeout   = 3 * time.Second
)

// NewResolver creates a container metadata resolver.
// It auto-detects the available container runtime.
func NewResolver(logger *zap.Logger) *Resolver {
	r := &Resolver{
		logger: logger,
		cache:  make(map[string]*cacheEntry),
	}
	r.runtime = r.detectRuntime()

	if r.runtime != "" {
		logger.Info("container runtime detected",
			zap.String("runtime", r.runtime))
	} else {
		logger.Info("no container runtime detected, container enrichment disabled")
	}

	return r
}

// Resolve returns container metadata for a given PID.
// Returns nil if the PID is not in a container.
func (r *Resolver) Resolve(pid int) *Info {
	if r.runtime == "" {
		return nil
	}

	// Read container ID from cgroup.
	containerID := r.getContainerID(pid)
	if containerID == "" {
		return nil
	}

	// Check cache.
	r.mu.RLock()
	if entry, ok := r.cache[containerID]; ok && time.Since(entry.timestamp) < cacheTTL {
		r.mu.RUnlock()
		return entry.info
	}
	r.mu.RUnlock()

	// Query runtime.
	info := r.queryRuntime(containerID)
	if info == nil {
		return nil
	}

	// Cache result.
	r.mu.Lock()
	if len(r.cache) >= cacheMaxSize {
		r.evictOldest()
	}
	r.cache[containerID] = &cacheEntry{info: info, timestamp: time.Now()}
	r.mu.Unlock()

	return info
}

// Runtime returns the detected container runtime name.
func (r *Resolver) Runtime() string {
	return r.runtime
}

// getContainerID reads the container ID from /proc/<pid>/cgroup.
func (r *Resolver) getContainerID(pid int) string {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Docker: "/docker/<id>" or "docker-<id>.scope"
		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/docker/")
			if len(parts) > 1 {
				return extractID(parts[1])
			}
		}
		if strings.Contains(line, "docker-") && strings.HasSuffix(line, ".scope") {
			if _, after, ok := strings.Cut(line, "docker-"); ok {
				return strings.TrimSuffix(after, ".scope")
			}
		}

		// containerd: "/containerd/<id>" or K8s cri pattern
		if strings.Contains(line, "/containerd/") {
			parts := strings.Split(line, "/containerd/")
			if len(parts) > 1 {
				return extractID(parts[1])
			}
		}

		// cri-o: "/crio-<id>"
		if strings.Contains(line, "/crio-") {
			parts := strings.Split(line, "/crio-")
			if len(parts) > 1 {
				return extractID(parts[1])
			}
		}

		// K8s containerd pattern: .../cri-containerd-<id>.scope
		if strings.Contains(line, "cri-containerd-") {
			if _, after, ok := strings.Cut(line, "cri-containerd-"); ok {
				return strings.TrimSuffix(extractID(after), ".scope")
			}
		}
	}

	return ""
}

// queryRuntime queries the container runtime for metadata.
func (r *Resolver) queryRuntime(containerID string) *Info {
	switch r.runtime {
	case "docker":
		return r.queryDocker(containerID)
	case "containerd":
		return r.queryContainerd(containerID)
	default:
		return nil
	}
}

// dockerInspect is the subset of docker inspect JSON we need.
type dockerInspect struct {
	ID     string            `json:"Id"`
	Name   string            `json:"Name"`
	Config *dockerConfig     `json:"Config"`
	Labels map[string]string `json:"-"`
}

type dockerConfig struct {
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

func (r *Resolver) queryDocker(containerID string) *Info {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "json", containerID).Output()
	if err != nil {
		return nil
	}

	var inspects []dockerInspect
	if err := json.Unmarshal(out, &inspects); err != nil || len(inspects) == 0 {
		return nil
	}

	d := inspects[0]
	info := &Info{
		ContainerID: containerID,
		Name:        strings.TrimPrefix(d.Name, "/"),
		Runtime:     "docker",
	}
	if d.Config != nil {
		info.Image = d.Config.Image
		info.Labels = d.Config.Labels
	}

	r.extractK8sLabels(info)
	return info
}

func (r *Resolver) queryContainerd(containerID string) *Info {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	// Try k8s.io namespace first (most common for K8s), then default.
	for _, ns := range []string{"k8s.io", "default"} {
		out, err := exec.CommandContext(ctx, "ctr", "-n", ns,
			"containers", "info", containerID).Output()
		if err != nil {
			continue
		}

		info := r.parseContainerdInfo(containerID, string(out))
		if info != nil {
			return info
		}
	}

	return nil
}

// parseContainerdInfo parses `ctr containers info` output.
func (r *Resolver) parseContainerdInfo(containerID, output string) *Info {
	info := &Info{
		ContainerID: containerID,
		Runtime:     "containerd",
		Labels:      make(map[string]string),
	}

	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "Image:"); ok {
			info.Image = strings.TrimSpace(after)
		}
		if strings.HasPrefix(line, "Labels:") {
			// Labels section follows, parse key=value pairs.
			continue
		}
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				info.Labels[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	r.extractK8sLabels(info)
	return info
}

// extractK8sLabels populates K8s fields from container labels.
func (r *Resolver) extractK8sLabels(info *Info) {
	if info.Labels == nil {
		return
	}
	// Standard K8s labels.
	if v, ok := info.Labels["io.kubernetes.pod.name"]; ok {
		info.PodName = v
	}
	if v, ok := info.Labels["io.kubernetes.pod.namespace"]; ok {
		info.Namespace = v
	}
	if v, ok := info.Labels["io.kubernetes.pod.uid"]; ok {
		info.PodUID = v
	}
	// Set name from K8s container name label if not set.
	if info.Name == "" {
		if v, ok := info.Labels["io.kubernetes.container.name"]; ok {
			info.Name = v
		}
	}
}

// detectRuntime checks which container runtime CLI is available.
func (r *Resolver) detectRuntime() string {
	// Check docker.
	if _, err := exec.LookPath("docker"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "docker", "info").Run(); err == nil {
			return "docker"
		}
	}

	// Check containerd (ctr).
	if _, err := exec.LookPath("ctr"); err == nil {
		return "containerd"
	}

	return ""
}

// evictOldest removes the oldest cache entry (must be called with lock held).
func (r *Resolver) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range r.cache {
		if first || v.timestamp.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.timestamp
			first = false
		}
	}
	if oldestKey != "" {
		delete(r.cache, oldestKey)
	}
}

// extractID extracts a container ID from a cgroup path segment.
func extractID(s string) string {
	// Remove trailing path components and .scope suffix.
	s = strings.Split(s, "/")[0]
	s = strings.TrimSuffix(s, ".scope")
	return s
}

// Cleanup removes expired cache entries.
func (r *Resolver) Cleanup() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	var removed int
	now := time.Now()
	for k, v := range r.cache {
		if now.Sub(v.timestamp) > cacheTTL {
			delete(r.cache, k)
			removed++
		}
	}
	return removed
}

// Stats returns cache size.
func (r *Resolver) Stats() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}
