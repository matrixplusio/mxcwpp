package imagescan

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// DockerfileFinding Dockerfile lint 产物。
type DockerfileFinding struct {
	Rule     string
	Severity string
	Line     int
	Snippet  string
	Hint     string
}

// DockerfileLinter 扫描 Dockerfile 常见反模式。
type DockerfileLinter struct{}

// NewDockerfileLinter 构造。
func NewDockerfileLinter() *DockerfileLinter { return &DockerfileLinter{} }

// Lint 扫描 Dockerfile 行。
func (l *DockerfileLinter) Lint(_ context.Context, reader io.Reader) ([]DockerfileFinding, error) {
	var findings []DockerfileFinding
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	hasHealthcheck := false
	hasUser := false
	hasUserRoot := false

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		upper := strings.ToUpper(line)

		// FROM xxx:latest
		if strings.HasPrefix(upper, "FROM ") {
			if strings.Contains(line, ":latest") || !strings.Contains(line, ":") {
				findings = append(findings, DockerfileFinding{
					Rule: "FROM_LATEST", Severity: "medium",
					Line: lineNo, Snippet: line,
					Hint: "FROM :latest 或无 tag, 构建不可复现",
				})
			}
		}

		// HEALTHCHECK
		if strings.HasPrefix(upper, "HEALTHCHECK ") {
			hasHealthcheck = true
		}

		// USER root / 默认 root
		if strings.HasPrefix(upper, "USER ") {
			hasUser = true
			rest := strings.TrimSpace(line[5:])
			if rest == "root" || rest == "0" {
				hasUserRoot = true
				findings = append(findings, DockerfileFinding{
					Rule: "USER_ROOT", Severity: "high",
					Line: lineNo, Snippet: line,
					Hint: "USER root 提升容器逃逸风险",
				})
			}
		}

		// curl|sh 远程脚本执行
		if strings.Contains(strings.ToLower(line), "curl") &&
			(strings.Contains(line, "| sh") || strings.Contains(line, "|sh") ||
				strings.Contains(line, "| bash") || strings.Contains(line, "|bash")) {
			findings = append(findings, DockerfileFinding{
				Rule: "CURL_PIPE_SH", Severity: "critical",
				Line: lineNo, Snippet: line,
				Hint: "curl | sh 远程脚本执行 (供应链风险)",
			})
		}

		// 敏感 ENV
		if strings.HasPrefix(upper, "ENV ") {
			lowered := strings.ToLower(line)
			if strings.Contains(lowered, "password=") ||
				strings.Contains(lowered, "secret=") ||
				strings.Contains(lowered, "api_key=") ||
				strings.Contains(lowered, "token=") {
				findings = append(findings, DockerfileFinding{
					Rule: "ENV_SECRET", Severity: "high",
					Line: lineNo, Snippet: line,
					Hint: "ENV 中硬编码 Secret (镜像层会持久化)",
				})
			}
		}

		// ADD instead of COPY (网络下载场景)
		if strings.HasPrefix(upper, "ADD ") && (strings.Contains(line, "http://") || strings.Contains(line, "https://")) {
			findings = append(findings, DockerfileFinding{
				Rule: "ADD_HTTP", Severity: "medium",
				Line: lineNo, Snippet: line,
				Hint: "ADD http(s) URL 缺校验, 建议 COPY 本地文件",
			})
		}
	}

	if !hasHealthcheck {
		findings = append(findings, DockerfileFinding{
			Rule: "NO_HEALTHCHECK", Severity: "low",
			Line: 0, Hint: "未定义 HEALTHCHECK 指令",
		})
	}
	if !hasUser || (hasUser && hasUserRoot) {
		findings = append(findings, DockerfileFinding{
			Rule: "NO_NONROOT_USER", Severity: "high",
			Line: 0, Hint: "未切换到非 root user (生产容器风险)",
		})
	}
	return findings, scanner.Err()
}
