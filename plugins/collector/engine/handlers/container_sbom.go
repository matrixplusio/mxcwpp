// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ContainerSBOMHandler 扫描运行中的容器内部包清单
// 与 SoftwareHandler 互补：SoftwareHandler 扫描宿主机包，ContainerSBOMHandler 扫描容器内
type ContainerSBOMHandler struct {
	Logger *zap.Logger
}

// containerRef 用于内部传递（runtime + id + image）
type containerRef struct {
	Runtime string // docker / containerd
	ID      string
	Image   string
}

// 单容器 exec 超时
const containerExecTimeout = 5 * time.Second

// 容器并发上限
const containerSBOMConcurrency = 4

// Collect 扫描运行中容器的 SBOM
func (h *ContainerSBOMHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var refs []containerRef

	// docker 列表（若 docker 不存在则跳过 docker 部分）
	if _, err := exec.LookPath("docker"); err == nil {
		dockerRefs, err := h.listDockerContainers(ctx)
		if err != nil {
			h.Logger.Debug("docker ps failed, skip docker SBOM", zap.Error(err))
		} else {
			refs = append(refs, dockerRefs...)
		}
	}

	// containerd 列表（crictl 优先，缺失则跳过整个 containerd 部分）
	if _, err := exec.LookPath("crictl"); err == nil {
		crictlRefs, err := h.listCrictlContainers(ctx)
		if err != nil {
			h.Logger.Debug("crictl ps failed, skip containerd SBOM", zap.Error(err))
		} else {
			refs = append(refs, crictlRefs...)
		}
	}

	if len(refs) == 0 {
		h.Logger.Debug("no running containers detected for SBOM scan")
		return nil, nil
	}

	// 并发扫描（限 4）
	results := h.scanContainersConcurrent(ctx, refs)

	h.Logger.Info("container SBOM finished",
		zap.Int("containers_scanned", len(refs)),
		zap.Int("packages", len(results)))

	return results, nil
}

// listDockerContainers 列运行中的 docker 容器（仅 running）
func (h *ContainerSBOMHandler) listDockerContainers(ctx context.Context) ([]containerRef, error) {
	// 取完整 ID
	idCmd := exec.CommandContext(ctx, "docker", "ps", "-q", "--no-trunc")
	idOut, err := idCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps -q failed: %w", err)
	}

	ids := splitNonEmptyLines(string(idOut))
	if len(ids) == 0 {
		return nil, nil
	}

	// 单独取 image（docker inspect 比 ps --format 更可靠）
	var refs []containerRef
	for _, id := range ids {
		image := h.dockerImage(ctx, id)
		refs = append(refs, containerRef{Runtime: "docker", ID: id, Image: image})
	}
	return refs, nil
}

// dockerImage 通过 docker inspect 取 image 名（失败则空）
func (h *ContainerSBOMHandler) dockerImage(ctx context.Context, id string) string {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "docker", "inspect", "--format", "{{.Config.Image}}", id).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// listCrictlContainers 列运行中的 containerd 容器
func (h *ContainerSBOMHandler) listCrictlContainers(ctx context.Context) ([]containerRef, error) {
	idCmd := exec.CommandContext(ctx, "crictl", "ps", "-q")
	idOut, err := idCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("crictl ps -q failed: %w", err)
	}
	ids := splitNonEmptyLines(string(idOut))
	if len(ids) == 0 {
		return nil, nil
	}

	var refs []containerRef
	for _, id := range ids {
		image := h.crictlImage(ctx, id)
		refs = append(refs, containerRef{Runtime: "containerd", ID: id, Image: image})
	}
	return refs, nil
}

// crictlImage 通过 crictl inspect 取 image（失败则空）
func (h *ContainerSBOMHandler) crictlImage(ctx context.Context, id string) string {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "crictl", "inspect", "--output", "go-template", "--template", "{{.status.image.image}}", id).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// scanContainersConcurrent 并发扫描容器 SBOM，并发度 = containerSBOMConcurrency
func (h *ContainerSBOMHandler) scanContainersConcurrent(ctx context.Context, refs []containerRef) []interface{} {
	var (
		mu      sync.Mutex
		results []interface{}
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, containerSBOMConcurrency)

	for _, ref := range refs {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(r containerRef) {
			defer wg.Done()
			defer func() { <-sem }()

			pkgs := h.scanOneContainer(ctx, r)
			if len(pkgs) == 0 {
				return
			}
			mu.Lock()
			results = append(results, pkgs...)
			mu.Unlock()
		}(ref)
	}

	wg.Wait()
	return results
}

// scanOneContainer 对单容器探 OS → 跑对应包管理器命令 → 解析输出
func (h *ContainerSBOMHandler) scanOneContainer(ctx context.Context, ref containerRef) []interface{} {
	distro := h.detectContainerOS(ctx, ref)
	if distro == "" {
		// distroless / scratch / 探测失败，跳过
		h.Logger.Debug("skip container: os undetected or unsupported",
			zap.String("runtime", ref.Runtime),
			zap.String("id", ref.ID))
		return nil
	}

	switch distro {
	case "rhel", "centos", "fedora", "amazon", "oracle", "rocky", "almalinux", "redhat":
		return h.scanRPM(ctx, ref, distro)
	case "debian", "ubuntu":
		return h.scanDEB(ctx, ref, distro)
	case "alpine":
		return h.scanAPK(ctx, ref, distro)
	default:
		return nil
	}
}

// detectContainerOS 通过 /etc/os-release 推测发行版
func (h *ContainerSBOMHandler) detectContainerOS(ctx context.Context, ref containerRef) string {
	out, err := h.execInContainer(ctx, ref, "cat", "/etc/os-release")
	if err != nil || len(out) == 0 {
		return ""
	}

	idLine := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			idLine = strings.TrimPrefix(line, "ID=")
			idLine = strings.Trim(idLine, "\"'")
			break
		}
	}

	return strings.ToLower(strings.TrimSpace(idLine))
}

// scanRPM 容器内 rpm -qa
func (h *ContainerSBOMHandler) scanRPM(ctx context.Context, ref containerRef, distro string) []interface{} {
	out, err := h.execInContainer(ctx, ref, "rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}|%{ARCH}\n")
	if err != nil {
		h.Logger.Debug("rpm -qa failed inside container",
			zap.String("id", ref.ID), zap.Error(err))
		return nil
	}

	var pkgs []interface{}
	for _, line := range splitNonEmptyLines(string(out)) {
		parts := strings.Split(line, "|")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		name, version := parts[0], parts[1]
		arch := ""
		if len(parts) > 2 {
			arch = parts[2]
		}
		pkgs = append(pkgs, buildContainerPkg(ref, "rpm", distro, name, version, arch))
	}
	return pkgs
}

// scanDEB 容器内 dpkg-query
func (h *ContainerSBOMHandler) scanDEB(ctx context.Context, ref containerRef, distro string) []interface{} {
	out, err := h.execInContainer(ctx, ref, "dpkg-query", "-W", "-f", "${Package}|${Version}|${Architecture}|${Status}\n")
	if err != nil {
		h.Logger.Debug("dpkg-query failed inside container",
			zap.String("id", ref.ID), zap.Error(err))
		return nil
	}

	var pkgs []interface{}
	for _, line := range splitNonEmptyLines(string(out)) {
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		if len(parts) >= 4 && !strings.Contains(parts[3], "installed") {
			continue
		}
		name, version := parts[0], parts[1]
		arch := ""
		if len(parts) > 2 {
			arch = parts[2]
		}
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, buildContainerPkg(ref, "deb", distro, name, version, arch))
	}
	return pkgs
}

// scanAPK 容器内 apk info -v
func (h *ContainerSBOMHandler) scanAPK(ctx context.Context, ref containerRef, distro string) []interface{} {
	out, err := h.execInContainer(ctx, ref, "apk", "info", "-v")
	if err != nil {
		h.Logger.Debug("apk info failed inside container",
			zap.String("id", ref.ID), zap.Error(err))
		return nil
	}

	var pkgs []interface{}
	for _, line := range splitNonEmptyLines(string(out)) {
		// 格式：name-version-release，例如 musl-1.2.4-r2
		// 拆分：version 是最后一个段（含 release），name 是剩下的
		idx := strings.LastIndex(line, "-")
		if idx <= 0 {
			continue
		}
		nameVer := line[:idx]
		release := line[idx+1:]
		idx2 := strings.LastIndex(nameVer, "-")
		if idx2 <= 0 {
			continue
		}
		name := nameVer[:idx2]
		version := nameVer[idx2+1:] + "-" + release
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, buildContainerPkg(ref, "apk", distro, name, version, ""))
	}
	return pkgs
}

// execInContainer 在容器内执行命令（5s 超时），自动选 docker 或 crictl
func (h *ContainerSBOMHandler) execInContainer(ctx context.Context, ref containerRef, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, containerExecTimeout)
	defer cancel()

	var cmd *exec.Cmd
	switch ref.Runtime {
	case "docker":
		fullArgs := append([]string{"exec", ref.ID, name}, args...)
		cmd = exec.CommandContext(cctx, "docker", fullArgs...)
	case "containerd":
		fullArgs := append([]string{"exec", ref.ID, name}, args...)
		cmd = exec.CommandContext(cctx, "crictl", fullArgs...)
	default:
		return nil, fmt.Errorf("unknown runtime: %s", ref.Runtime)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s exec failed: %w (stderr=%s)", ref.Runtime, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// buildContainerPkg 构造统一格式（与 software.go 一致的 map 输出）
func buildContainerPkg(ref containerRef, pkgType, distro, name, version, arch string) map[string]interface{} {
	purl := fmt.Sprintf("pkg:%s/%s/%s@%s",
		pkgType,
		url.PathEscape(distro),
		url.PathEscape(name),
		url.PathEscape(version))
	q := "container=" + url.QueryEscape(ref.ID)
	if arch != "" {
		q = "arch=" + url.QueryEscape(arch) + "&" + q
	}
	purl += "?" + q

	return map[string]interface{}{
		"name":            name,
		"version":         version,
		"architecture":    arch,
		"collected_at":    time.Now().Format(time.RFC3339),
		"package_type":    pkgType,
		"purl":            purl,
		"source_file":     fmt.Sprintf("container:%s:%s", ref.ID, ref.Image),
		"container_id":    ref.ID,
		"container_image": ref.Image,
		"runtime":         ref.Runtime,
	}
}

// splitNonEmptyLines 拆分非空行（trim 后）
func splitNonEmptyLines(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
