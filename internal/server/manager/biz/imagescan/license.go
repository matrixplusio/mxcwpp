package imagescan

// License 扫描 (P3-8).
//
// 识别镜像内文件的开源 license, 标记 viral (GPL/AGPL) + restrictive 风险:
//
//	GPL-2.0 / GPL-3.0     — viral (静态链接传染)
//	AGPL-3.0             — viral over network
//	LGPL-2.1 / LGPL-3.0  — 动态链接相对宽松
//	MPL-2.0              — file-level copyleft
//	Apache-2.0           — permissive (商业友好)
//	MIT / BSD-3-Clause   — permissive
//	Proprietary          — 非开源 (商业 license)
//	Unknown              — 未识别
//
// 商业产品集成 GPL 代码可能被强制开源源码; 本扫描在 CI/CD 早期阻断风险。
//
// 检测方法:
//   1. 找 LICENSE / COPYING / LICENSE.txt / NOTICE 等标准文件
//   2. 读前 8 KB → 匹配已知 license header 关键字符串
//   3. 第二轮: package metadata (package.json/pom.xml/setup.py/Cargo.toml) license 字段
//
// 误报控制: 仅文件命中或 metadata 命中即记录, 不两者同时要求。

import (
	"bufio"
	"context"
	"io"
	"path/filepath"
	"strings"
)

// LicenseFinding 单条 license 命中.
type LicenseFinding struct {
	Path      string `json:"path"`
	License   string `json:"license"`    // SPDX ID
	RiskLevel string `json:"risk_level"` // viral / restrictive / permissive / unknown
	Source    string `json:"source"`     // license_file / package_metadata
	Snippet   string `json:"snippet,omitempty"`
}

// LicenseScanner 配置.
type LicenseScanner struct {
	// 风险分级: viral 阻断 CI, restrictive 警告, permissive 通过.
	ViralBlocks bool
}

// NewLicenseScanner 构造.
func NewLicenseScanner() *LicenseScanner {
	return &LicenseScanner{ViralBlocks: true}
}

// licenseSignatures 已知 license 文本关键字.
//
// 顺序优先级: 越精确越靠前 (AGPL > GPL > LGPL).
var licenseSignatures = []struct {
	SPDXID    string
	RiskLevel string
	Markers   []string // 任一 marker 命中即认定
}{
	{"AGPL-3.0", "viral", []string{
		"GNU AFFERO GENERAL PUBLIC LICENSE",
		"Version 3, 19 November 2007",
		"under the AGPL",
	}},
	{"GPL-3.0", "viral", []string{
		"GNU GENERAL PUBLIC LICENSE",
		"Version 3, 29 June 2007",
		"http://www.gnu.org/licenses/gpl-3.0",
	}},
	{"GPL-2.0", "viral", []string{
		"GNU GENERAL PUBLIC LICENSE",
		"Version 2, June 1991",
		"http://www.gnu.org/licenses/gpl-2.0",
	}},
	{"LGPL-3.0", "restrictive", []string{
		"GNU LESSER GENERAL PUBLIC LICENSE",
		"Version 3",
		"http://www.gnu.org/licenses/lgpl-3.0",
	}},
	{"LGPL-2.1", "restrictive", []string{
		"GNU LESSER GENERAL PUBLIC LICENSE",
		"Version 2.1",
		"http://www.gnu.org/licenses/lgpl-2.1",
	}},
	{"MPL-2.0", "restrictive", []string{
		"Mozilla Public License Version 2.0",
		"http://mozilla.org/MPL/2.0/",
	}},
	{"Apache-2.0", "permissive", []string{
		"Apache License, Version 2.0",
		"http://www.apache.org/licenses/LICENSE-2.0",
	}},
	{"MIT", "permissive", []string{
		"Permission is hereby granted, free of charge",
		"THE SOFTWARE IS PROVIDED \"AS IS\"",
		"MIT License",
	}},
	{"BSD-3-Clause", "permissive", []string{
		"Redistributions of source code must retain",
		"Redistributions in binary form must reproduce",
		"BSD 3-Clause",
	}},
	{"BSD-2-Clause", "permissive", []string{
		"BSD 2-Clause License",
	}},
	{"ISC", "permissive", []string{
		"Permission to use, copy, modify, and/or distribute this software",
		"ISC License",
	}},
	{"Unlicense", "permissive", []string{
		"This is free and unencumbered software released into the public domain",
	}},
}

// Scan 扫描 reader 内容, 识别 license.
func (s *LicenseScanner) Scan(_ context.Context, path string, reader io.Reader) (*LicenseFinding, error) {
	const maxScan = 8192
	buf := make([]byte, maxScan)
	br := bufio.NewReader(reader)
	n, _ := io.ReadFull(br, buf)
	body := strings.ToUpper(string(buf[:n]))

	for _, sig := range licenseSignatures {
		for _, marker := range sig.Markers {
			if strings.Contains(body, strings.ToUpper(marker)) {
				snippet := marker
				if len(snippet) > 80 {
					snippet = snippet[:80] + "..."
				}
				return &LicenseFinding{
					Path:      path,
					License:   sig.SPDXID,
					RiskLevel: sig.RiskLevel,
					Source:    "license_file",
					Snippet:   snippet,
				}, nil
			}
		}
	}

	return &LicenseFinding{
		Path:      path,
		License:   "Unknown",
		RiskLevel: "unknown",
		Source:    "license_file",
	}, nil
}

// IsLicenseFile 判断文件名是否典型 license 文件.
func IsLicenseFile(filename string) bool {
	base := strings.ToUpper(filepath.Base(filename))
	switch base {
	case "LICENSE", "LICENSE.TXT", "LICENSE.MD",
		"COPYING", "COPYING.TXT", "COPYING.MD",
		"COPYRIGHT", "COPYRIGHT.TXT",
		"NOTICE", "NOTICE.TXT",
		"LICENCE", "LICENCE.TXT":
		return true
	}
	// LICENSE-MIT / LICENSE-APACHE 等
	if strings.HasPrefix(base, "LICENSE-") || strings.HasPrefix(base, "LICENSE.") {
		return true
	}
	return false
}

// ShouldBlock 给定 finding 是否应在 CI 阻断 (viral license).
func (s *LicenseScanner) ShouldBlock(f *LicenseFinding) bool {
	if s.ViralBlocks && f.RiskLevel == "viral" {
		return true
	}
	return false
}
