// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/plugins/collector/engine"
)

// SoftwareHandler 是软件包采集器
type SoftwareHandler struct {
	Logger *zap.Logger
}

// Collect 采集软件包信息
func (h *SoftwareHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var packages []interface{}

	// 检测包管理器类型
	packageManager := h.detectPackageManager()
	if packageManager == "" {
		h.Logger.Warn("no supported package manager found")
		return packages, nil
	}

	h.Logger.Debug("detected package manager", zap.String("type", packageManager))

	// 根据包管理器类型采集
	switch packageManager {
	case "rpm":
		rpmPackages, err := h.collectRPMPackages(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to collect RPM packages: %w", err)
		}
		packages = append(packages, rpmPackages...)
	case "deb":
		debPackages, err := h.collectDEBPackages(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to collect DEB packages: %w", err)
		}
		packages = append(packages, debPackages...)
	}

	return packages, nil
}

// detectPackageManager 检测包管理器类型
func (h *SoftwareHandler) detectPackageManager() string {
	// 检测 RPM
	if _, err := exec.LookPath("rpm"); err == nil {
		return "rpm"
	}

	// 检测 DPKG
	if _, err := exec.LookPath("dpkg"); err == nil {
		return "deb"
	}

	return ""
}

// collectRPMPackages 采集 RPM 包信息
func (h *SoftwareHandler) collectRPMPackages(ctx context.Context) ([]interface{}, error) {
	var packages []interface{}

	// 执行 rpm -qa --queryformat
	// NEVRA 完整字段：NAME|EPOCH|VERSION|RELEASE|ARCH|VENDOR|INSTALLTIME
	// %{EPOCH} 不存在时 rpm 输出 "(none)"，调用方需归一化为空串
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{VENDOR}|%{INSTALLTIME}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute rpm: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return packages, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}

		epoch := parts[1]
		if epoch == "(none)" {
			epoch = ""
		}

		pkg := &engine.SoftwareAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			Name:         parts[0],
			Epoch:        epoch,
			Version:      parts[2],
			Release:      parts[3],
			Architecture: parts[4],
			PackageType:  "rpm",
		}

		if len(parts) > 5 && parts[5] != "" {
			pkg.Vendor = parts[5]
		}

		if len(parts) > 6 && parts[6] != "" {
			pkg.InstallTime = parts[6]
		}

		// 生成 PURL: pkg:rpm/{vendor}/{name}@{version}?arch={arch}
		pkg.PURL = buildRPMPURL(pkg.Name, pkg.Version, pkg.Architecture, pkg.Vendor)

		packages = append(packages, pkg)
	}

	return packages, nil
}

// collectDEBPackages 采集 DEB 包信息
func (h *SoftwareHandler) collectDEBPackages(ctx context.Context) ([]interface{}, error) {
	var packages []interface{}

	// 执行 dpkg-query
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${Package}|${Version}|${Architecture}|${Status}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute dpkg-query: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return packages, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		// 只采集已安装的包（Status 包含 "installed"）
		status := ""
		if len(parts) > 3 {
			status = parts[3]
		}
		if !strings.Contains(status, "installed") {
			continue
		}

		pkg := &engine.SoftwareAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			Name:         parts[0],
			Version:      parts[1],
			Architecture: parts[2],
			PackageType:  "deb",
		}

		// 生成 PURL: pkg:deb/debian/{name}@{version}?arch={arch}
		pkg.PURL = buildDEBPURL(pkg.Name, pkg.Version, pkg.Architecture)

		packages = append(packages, pkg)
	}

	return packages, nil
}

// buildRPMPURL 生成 RPM 包的 Package URL
// 格式: pkg:rpm/{namespace}/{name}@{version}?arch={arch}
func buildRPMPURL(name, version, arch, vendor string) string {
	namespace := "redhat"
	if vendor != "" {
		ns := strings.ToLower(vendor)
		switch {
		case strings.Contains(ns, "centos"):
			namespace = "centos"
		case strings.Contains(ns, "fedora"):
			namespace = "fedora"
		case strings.Contains(ns, "suse") || strings.Contains(ns, "opensuse"):
			namespace = "opensuse"
		case strings.Contains(ns, "amazon"):
			namespace = "amazon"
		case strings.Contains(ns, "oracle"):
			namespace = "oracle"
		case strings.Contains(ns, "red hat") || strings.Contains(ns, "redhat"):
			namespace = "redhat"
		}
	}
	purl := fmt.Sprintf("pkg:rpm/%s/%s@%s", namespace, url.PathEscape(name), url.PathEscape(version))
	if arch != "" && arch != "(none)" {
		purl += "?arch=" + url.QueryEscape(arch)
	}
	return purl
}

// buildDEBPURL 生成 DEB 包的 Package URL
// 格式: pkg:deb/debian/{name}@{version}?arch={arch}
func buildDEBPURL(name, version, arch string) string {
	purl := fmt.Sprintf("pkg:deb/debian/%s@%s", url.PathEscape(name), url.PathEscape(version))
	if arch != "" {
		purl += "?arch=" + url.QueryEscape(arch)
	}
	return purl
}
