package parsers

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// ParsePipRequirements 解析 requirements.txt
// 格式：package==version 或 package>=version 或 package
func ParsePipRequirements(r io.Reader) ([]Dependency, error) {
	var deps []Dependency

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// 移除行内注释
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// 移除环境标记 ; python_version >= "3.6"
		if idx := strings.Index(line, ";"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// 移除 extras [security]
		name := line
		if idx := strings.Index(name, "["); idx != -1 {
			name = name[:idx]
		}

		// 分割版本号
		var version string
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if idx := strings.Index(name, sep); idx != -1 {
				version = strings.TrimSpace(name[idx+len(sep):])
				name = strings.TrimSpace(name[:idx])
				break
			}
		}

		if name == "" {
			continue
		}

		// PyPI 包名标准化：小写 + 下划线替换连字符
		pname := strings.ToLower(strings.ReplaceAll(name, "-", "_"))

		dep := Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "PyPI",
		}
		if version != "" {
			dep.PURL = fmt.Sprintf("pkg:pypi/%s@%s", pname, version)
		}
		deps = append(deps, dep)
	}

	return deps, scanner.Err()
}
