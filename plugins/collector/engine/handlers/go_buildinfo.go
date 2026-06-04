package handlers

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Go static binary 扫描根目录（glob 通配）
var goBuildInfoScanGlobs = []string{
	"/usr/local/bin",
	"/usr/bin",
	"/opt/*/bin",
	"/var/lib/*/bin",
	"/home/*/go/bin",
}

// 单个二进制大小上限：超过则跳过（极个别 fat binary）
const goBinaryMaxSize = 200 * 1024 * 1024 // 200MB

// 单二进制最小大小：太小（< 1KB）通常不是 Go 程序
const goBinaryMinSize = 1024

// 扫描深度（相对于 glob 展开后的目录）
const goBuildInfoMaxDepth = 3

// 跳过的目录名
var goBuildInfoSkipDirs = map[string]struct{}{
	".git":   {},
	".cache": {},
}

// GoBuildInfoHandler 扫描 Go static binary 内嵌的 buildinfo，解析主模块及依赖
type GoBuildInfoHandler struct {
	Logger    *zap.Logger
	ScanGlobs []string
}

// Collect 实现 engine.Handler 接口
func (h *GoBuildInfoHandler) Collect(ctx context.Context) ([]interface{}, error) {
	globs := h.ScanGlobs
	if len(globs) == 0 {
		globs = goBuildInfoScanGlobs
	}

	var (
		results []interface{}
		// path@version 去重，避免多 binary 携带相同依赖被重复入库
		seen        = make(map[string]struct{})
		binariesHit = 0
	)

	// 展开 glob，得到所有真实存在的 bin 目录
	var binDirs []string
	for _, pattern := range globs {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			h.Logger.Debug("glob 展开失败", zap.String("pattern", pattern), zap.Error(err))
			continue
		}
		binDirs = append(binDirs, matches...)
	}

	for _, dir := range binDirs {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		found, hit, err := h.scanDir(ctx, dir, seen)
		if err != nil {
			h.Logger.Debug("Go buildinfo 扫描目录失败", zap.String("dir", dir), zap.Error(err))
			continue
		}
		results = append(results, found...)
		binariesHit += hit
	}

	h.Logger.Info("Go buildinfo 扫描完成",
		zap.Int("bin_dirs", len(binDirs)),
		zap.Int("binaries_with_buildinfo", binariesHit),
		zap.Int("total_modules", len(results)))
	return results, nil
}

// scanDir 扫描单个目录下的可执行文件
// 返回：模块列表、命中 buildinfo 的 binary 数、错误
func (h *GoBuildInfoHandler) scanDir(ctx context.Context, root string, seen map[string]struct{}) ([]interface{}, int, error) {
	var results []interface{}
	binariesHit := 0
	baseDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 跳过无权限
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		depth := strings.Count(path, string(filepath.Separator)) - baseDepth
		if depth > goBuildInfoMaxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if _, skip := goBuildInfoSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		// 仅处理常规文件
		if !info.Mode().IsRegular() {
			return nil
		}
		// 必须可执行（任一 x 位）
		if info.Mode().Perm()&0o111 == 0 {
			return nil
		}
		// 大小过滤
		size := info.Size()
		if size < goBinaryMinSize || size > goBinaryMaxSize {
			return nil
		}
		// 跳过 shell 脚本（首字节判定）
		if isShellScript(path) {
			return nil
		}

		mods, ok := h.readBuildInfo(path)
		if !ok {
			return nil
		}
		binariesHit++

		for _, m := range mods {
			key, _ := m["purl"].(string)
			if key == "" {
				name, _ := m["name"].(string)
				version, _ := m["version"].(string)
				key = name + "@" + version
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			results = append(results, m)
		}
		return nil
	})

	return results, binariesHit, err
}

// readBuildInfo 用 debug/buildinfo 解析单个 binary
// 返回 [主模块, dep1, dep2 ...]，无 buildinfo / 非 Go binary 时 ok=false
func (h *GoBuildInfoHandler) readBuildInfo(path string) ([]map[string]interface{}, bool) {
	defer func() {
		// 极少数边界损坏文件可能让 debug/buildinfo 内部 panic
		if r := recover(); r != nil {
			h.Logger.Debug("buildinfo panic", zap.String("path", path), zap.Any("recover", r))
		}
	}()

	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var out []map[string]interface{}

	// 主模块 = 实际部署的 Go 服务本体
	//
	// scope=system 表示 "this is the daemon/service running on disk"，
	// package_type=go-binary 与依赖的 go-module 区分。
	// 漏洞匹配引擎按 (scope, package_type) 决定是否参与 CPE daemon 维度匹配。
	mainPath := info.Main.Path
	mainVer := info.Main.Version
	if mainPath != "" && mainVer != "" && mainVer != "(devel)" {
		binaryName := filepath.Base(path)
		out = append(out, map[string]interface{}{
			"name":             "go-binary:" + binaryName,
			"version":          mainVer,
			"collected_at":     time.Now().Format(time.RFC3339),
			"package_type":     "go-binary",
			"scope":            "system",
			"source_handler":   "go_buildinfo",
			"host_binary_path": path,
			"ecosystem":        "Go",
			"purl":             fmt.Sprintf("pkg:golang/%s@%s", url.PathEscape(mainPath), url.PathEscape(mainVer)),
			"source_file":      path,
		})
	}

	// 依赖模块 = 被主模块静态链接进 binary 的库
	//
	// scope=embedded 表示"library code linked into main binary"，
	// **必须**在漏洞匹配时与 NVD daemon CPE（如 cpe:2.3:a:docker:docker）
	// 隔离 — 否则任何 Go 服务嵌入 github.com/docker/docker SDK 都会被
	// 误报为 docker daemon CVE（实测 G02-UAT 3 台无 docker 仍报 docker
	// 3 条 CVE 即此根因）。
	//
	// embedded 依赖仅参与 PURL 维度匹配（OSV pkg:golang/<path>@<ver>），
	// 不参与 CPE 应用本体匹配。
	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}
		depPath := dep.Path
		depVer := dep.Version
		// replace 指令：实际版本走 Replace 字段
		if dep.Replace != nil && dep.Replace.Path != "" {
			depPath = dep.Replace.Path
			if dep.Replace.Version != "" {
				depVer = dep.Replace.Version
			}
		}
		if depPath == "" || depVer == "" || depVer == "(devel)" {
			continue
		}
		out = append(out, map[string]interface{}{
			"name":             depPath,
			"version":          depVer,
			"collected_at":     time.Now().Format(time.RFC3339),
			"package_type":     "go-module",
			"scope":            "embedded",
			"source_handler":   "go_buildinfo",
			"host_binary_path": path,
			"ecosystem":        "Go",
			"purl":             fmt.Sprintf("pkg:golang/%s@%s", url.PathEscape(depPath), url.PathEscape(depVer)),
			"source_file":      path,
		})
	}

	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// isShellScript 通过首 2 字节判定 shebang（避免对脚本调用 buildinfo.ReadFile）
func isShellScript(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var buf [2]byte
	n, _ := f.Read(buf[:])
	if n < 2 {
		return false
	}
	return buf[0] == '#' && buf[1] == '!'
}
