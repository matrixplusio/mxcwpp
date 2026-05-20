package parsers

import (
	"encoding/xml"
	"fmt"
	"io"
)

// pomProject Maven pom.xml 结构（简化）
type pomProject struct {
	XMLName      xml.Name      `xml:"project"`
	Dependencies pomDepSection `xml:"dependencies"`
}

type pomDepSection struct {
	Dependencies []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// ParseMavenPOM 解析 pom.xml
func ParseMavenPOM(r io.Reader) ([]Dependency, error) {
	var project pomProject
	decoder := xml.NewDecoder(r)
	if err := decoder.Decode(&project); err != nil {
		return nil, fmt.Errorf("解析 pom.xml 失败: %w", err)
	}

	var deps []Dependency
	for _, d := range project.Dependencies.Dependencies {
		if d.GroupID == "" || d.ArtifactID == "" {
			continue
		}
		// 跳过 test scope
		if d.Scope == "test" {
			continue
		}
		// 跳过 Maven 变量引用 ${xxx}
		if d.Version == "" || d.Version[0] == '$' {
			continue
		}

		deps = append(deps, Dependency{
			Name:      d.GroupID + ":" + d.ArtifactID,
			Version:   d.Version,
			PURL:      fmt.Sprintf("pkg:maven/%s/%s@%s", d.GroupID, d.ArtifactID, d.Version),
			Ecosystem: "Maven",
		})
	}

	return deps, nil
}
