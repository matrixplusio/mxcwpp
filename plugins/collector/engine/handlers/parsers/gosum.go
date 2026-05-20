// Package parsers 提供各语言依赖文件的解析器
package parsers

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Dependency 通用依赖信息
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl"`
	Ecosystem string `json:"ecosystem"`
}

// ParseGoSum 解析 go.sum 文件
// go.sum 每行格式：module version hash
// 例：golang.org/x/crypto v0.17.0 h1:abcdef/...=
// 同一 module+version 会出现两行（一行 /go.mod hash，一行源码 hash），需去重
func ParseGoSum(r io.Reader) ([]Dependency, error) {
	seen := make(map[string]struct{})
	var deps []Dependency

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		module := parts[0]
		version := parts[1]

		// 去掉 /go.mod 后缀的版本标记
		version = strings.TrimSuffix(version, "/go.mod")

		// 去掉 v 前缀
		cleanVersion := strings.TrimPrefix(version, "v")

		key := module + "@" + cleanVersion
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		deps = append(deps, Dependency{
			Name:      module,
			Version:   cleanVersion,
			PURL:      fmt.Sprintf("pkg:golang/%s@%s", module, cleanVersion),
			Ecosystem: "Go",
		})
	}

	return deps, scanner.Err()
}
