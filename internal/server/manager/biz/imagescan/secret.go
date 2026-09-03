// Package imagescan 实现镜像/文件 Secret 检测 + Dockerfile lint 等深度扫描。
//
// 设计文档: ref/05-容器K8s.md §5 + docs/vuln-module-design.md
//
// 三类扫描:
//   - Secret (本文件): API Key/Token/Private Key/Password 等
//   - Dockerfile (dockerfile.go): :latest / root user / no-healthcheck / curl|sh
//   - License (license.go,留 PR): 商业 license 冲突 / GPL 传染
package imagescan

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"strings"
)

// SecretRule 是单条 Secret 检测规则。
type SecretRule struct {
	Name     string
	Severity string
	Regex    *regexp.Regexp
	Hint     string
}

// SecretFinding 是扫描产物。
type SecretFinding struct {
	Rule     string
	Severity string
	File     string
	Line     int
	Snippet  string
	Hint     string
}

// SecretScanner 扫描文件/镜像层中的硬编码 Secret。
type SecretScanner struct {
	rules []SecretRule
}

// NewSecretScanner 构造内置规则集 (~ trufflehog/gitleaks 子集)。
func NewSecretScanner() *SecretScanner {
	return &SecretScanner{
		rules: []SecretRule{
			{
				Name: "AWS_ACCESS_KEY_ID", Severity: "critical",
				Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
				Hint:  "AWS Access Key ID",
			},
			{
				Name: "AWS_SECRET_KEY", Severity: "critical",
				Regex: regexp.MustCompile(`(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key[\s:=]+['"]?([A-Za-z0-9/+]{40})['"]?`),
				Hint:  "AWS Secret Access Key",
			},
			{
				Name: "GCP_SERVICE_ACCOUNT", Severity: "critical",
				Regex: regexp.MustCompile(`"private_key_id":\s*"[a-f0-9]{40}"`),
				Hint:  "GCP service account JSON",
			},
			{
				Name: "GITHUB_PAT", Severity: "critical",
				Regex: regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
				Hint:  "GitHub Personal Access Token",
			},
			{
				Name: "GITHUB_OAUTH", Severity: "high",
				Regex: regexp.MustCompile(`gho_[A-Za-z0-9]{36,}`),
				Hint:  "GitHub OAuth token",
			},
			{
				Name: "STRIPE_LIVE_KEY", Severity: "critical",
				Regex: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
				Hint:  "Stripe live secret key",
			},
			{
				Name: "SLACK_TOKEN", Severity: "high",
				Regex: regexp.MustCompile(`xox[abprs]-[0-9]+-[0-9]+-[0-9a-zA-Z]+`),
				Hint:  "Slack token",
			},
			{
				Name: "JWT_TOKEN", Severity: "medium",
				Regex: regexp.MustCompile(`eyJ[A-Za-z0-9_=-]{20,}\.eyJ[A-Za-z0-9_=-]{20,}\.[A-Za-z0-9_=-]+`),
				Hint:  "JWT Token (可能为短期 token, 仍建议轮转)",
			},
			{
				Name: "PRIVATE_KEY_PEM", Severity: "critical",
				Regex: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
				Hint:  "PEM 私钥",
			},
			{
				Name: "GENERIC_API_KEY", Severity: "medium",
				Regex: regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*['"][^'"\n]{16,}['"]`),
				Hint:  "通用 API Key/Secret 形式",
			},
			{
				Name: "DASHSCOPE_API_KEY", Severity: "high",
				Regex: regexp.MustCompile(`sk-[a-f0-9]{32}`),
				Hint:  "阿里 DashScope/通义 API key",
			},
			{
				Name: "OPENAI_API_KEY", Severity: "high",
				Regex: regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9]{40,}`),
				Hint:  "OpenAI API Key (含 sk-proj 项目级)",
			},
		},
	}
}

// Scan 逐行扫描 reader 中的 Secret 模式。
func (s *SecretScanner) Scan(_ context.Context, file string, reader io.Reader) ([]SecretFinding, error) {
	var findings []SecretFinding
	scanner := bufio.NewScanner(reader)
	// 单行长度上限 1MB
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if line == "" {
			continue
		}
		// 跳过 commented out
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, r := range s.rules {
			loc := r.Regex.FindStringIndex(line)
			if loc == nil {
				continue
			}
			start := loc[0]
			end := loc[1]
			if end-start > 200 {
				end = start + 200
			}
			findings = append(findings, SecretFinding{
				Rule:     r.Name,
				Severity: r.Severity,
				File:     file,
				Line:     lineNo,
				Snippet:  line[start:end],
				Hint:     r.Hint,
			})
		}
	}
	return findings, scanner.Err()
}
