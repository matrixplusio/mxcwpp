package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// npmLockfile package-lock.json 结构
type npmLockfile struct {
	Packages     map[string]npmPackage `json:"packages"`
	Dependencies map[string]npmDep     `json:"dependencies"` // v1 格式兼容
}

type npmPackage struct {
	Version string `json:"version"`
}

type npmDep struct {
	Version string `json:"version"`
}

// ParseNPMLockfile 解析 package-lock.json
func ParseNPMLockfile(r io.Reader) ([]Dependency, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("读取 package-lock.json 失败: %w", err)
	}

	var lockfile npmLockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("解析 package-lock.json 失败: %w", err)
	}

	var deps []Dependency

	// v2/v3 格式（packages 字段）
	if len(lockfile.Packages) > 0 {
		for path, pkg := range lockfile.Packages {
			if path == "" || pkg.Version == "" {
				continue // 跳过根项目
			}
			// 路径格式：node_modules/express 或 node_modules/@scope/name
			name := strings.TrimPrefix(path, "node_modules/")
			if name == "" || strings.Contains(name, "node_modules/") {
				continue // 跳过嵌套依赖，只保留顶层
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   pkg.Version,
				PURL:      fmt.Sprintf("pkg:npm/%s@%s", name, pkg.Version),
				Ecosystem: "npm",
			})
		}
		return deps, nil
	}

	// v1 格式（dependencies 字段）
	for name, dep := range lockfile.Dependencies {
		if dep.Version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   dep.Version,
			PURL:      fmt.Sprintf("pkg:npm/%s@%s", name, dep.Version),
			Ecosystem: "npm",
		})
	}

	return deps, nil
}
