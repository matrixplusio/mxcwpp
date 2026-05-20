package handlers

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/plugins/collector/engine/handlers/parsers"
)

// 默认扫描目录
var defaultScanDirs = []string{
	"/opt",
	"/home",
	"/var/www",
	"/srv",
	"/usr/local",
}

// 最大扫描深度
const maxScanDepth = 5

// 单个文件大小限制 10MB
const maxFileSize = 10 * 1024 * 1024

// 已知依赖文件名 → 解析器映射
var depFileNames = map[string]string{
	"go.sum":            "go",
	"package-lock.json": "npm",
	"yarn.lock":         "yarn",
	"requirements.txt":  "pip",
	"Pipfile.lock":      "pipfile",
	"poetry.lock":       "poetry",
	"pom.xml":           "maven",
	"build.gradle":      "gradle",
	"build.gradle.kts":  "gradle",
	"Cargo.lock":        "cargo",
}

// DepScannerHandler 语言依赖文件扫描器
type DepScannerHandler struct {
	Logger   *zap.Logger
	ScanDirs []string // 可配置扫描目录
}

// Collect 扫描并解析语言依赖文件
func (h *DepScannerHandler) Collect(ctx context.Context) ([]interface{}, error) {
	dirs := h.ScanDirs
	if len(dirs) == 0 {
		dirs = defaultScanDirs
	}

	var results []interface{}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		deps, err := h.scanDir(ctx, dir)
		if err != nil {
			h.Logger.Warn("扫描目录失败", zap.String("dir", dir), zap.Error(err))
			continue
		}
		results = append(results, deps...)
	}

	h.Logger.Info("语言依赖扫描完成", zap.Int("total_deps", len(results)))
	return results, nil
}

// scanDir 递归扫描目录中的依赖文件
func (h *DepScannerHandler) scanDir(ctx context.Context, root string) ([]interface{}, error) {
	var results []interface{}
	baseDepth := strings.Count(root, string(filepath.Separator))

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 跳过无权限的目录
		}

		// 检查 context
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 控制扫描深度
		depth := strings.Count(path, string(filepath.Separator)) - baseDepth
		if depth > maxScanDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// 跳过常见无关目录
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".svn" || name == "vendor" || name == "__pycache__" || name == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}

		// 检查文件名
		fileName := d.Name()
		parserType, ok := depFileNames[fileName]
		if !ok {
			return nil
		}

		// 检查文件大小
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize || info.Size() == 0 {
			return nil
		}

		// 解析依赖文件
		deps, err := h.parseDepFile(path, parserType)
		if err != nil {
			h.Logger.Debug("解析依赖文件失败", zap.String("path", path), zap.Error(err))
			return nil
		}

		for _, dep := range deps {
			results = append(results, map[string]interface{}{
				"name":        dep.Name,
				"version":     dep.Version,
				"purl":        dep.PURL,
				"ecosystem":   dep.Ecosystem,
				"source_file": path,
			})
		}

		return nil
	})

	return results, err
}

// parseDepFile 调用对应解析器
func (h *DepScannerHandler) parseDepFile(path, parserType string) ([]parsers.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	switch parserType {
	case "go":
		return parsers.ParseGoSum(f)
	case "npm":
		return parsers.ParseNPMLockfile(f)
	case "pip":
		return parsers.ParsePipRequirements(f)
	case "maven":
		return parsers.ParseMavenPOM(f)
	case "cargo":
		return parsers.ParseCargoLock(f)
	default:
		return nil, nil // yarn, pipfile, poetry, gradle 暂不支持
	}
}
