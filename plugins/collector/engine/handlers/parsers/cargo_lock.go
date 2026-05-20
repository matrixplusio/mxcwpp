package parsers

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// ParseCargoLock 解析 Cargo.lock (TOML 格式)
// 每个 [[package]] 块包含 name 和 version
func ParseCargoLock(r io.Reader) ([]Dependency, error) {
	var deps []Dependency
	var currentName, currentVersion string
	inPackage := false

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			// 保存上一个 package
			if inPackage && currentName != "" && currentVersion != "" {
				deps = append(deps, Dependency{
					Name:      currentName,
					Version:   currentVersion,
					PURL:      fmt.Sprintf("pkg:cargo/%s@%s", currentName, currentVersion),
					Ecosystem: "Cargo",
				})
			}
			currentName = ""
			currentVersion = ""
			inPackage = true
			continue
		}

		if !inPackage {
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
		} else if strings.HasPrefix(line, "version = ") {
			currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
		}
	}

	// 最后一个 package
	if inPackage && currentName != "" && currentVersion != "" {
		deps = append(deps, Dependency{
			Name:      currentName,
			Version:   currentVersion,
			PURL:      fmt.Sprintf("pkg:cargo/%s@%s", currentName, currentVersion),
			Ecosystem: "Cargo",
		})
	}

	return deps, scanner.Err()
}
