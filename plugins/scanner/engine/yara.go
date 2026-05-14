package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	yaraRulesDir = "/var/mxsec/yara-rules"
	yaraBinary   = "yr" // YARA-X CLI
)

// YARAScanner 基于 YARA-X CLI 的扫描器
type YARAScanner struct {
	logger   *zap.Logger
	rulesDir string
}

// NewYARAScanner 创建 YARA-X 扫描器
func NewYARAScanner(logger *zap.Logger) *YARAScanner {
	rulesDir := yaraRulesDir
	// 如果插件目录下有 yara-rules，优先使用
	if pluginDir := os.Getenv("PLUGIN_DIR"); pluginDir != "" {
		localRules := filepath.Join(pluginDir, "yara-rules")
		if info, err := os.Stat(localRules); err == nil && info.IsDir() {
			rulesDir = localRules
		}
	}
	return &YARAScanner{
		logger:   logger,
		rulesDir: rulesDir,
	}
}

// Available 检查 yr (YARA-X) 是否可用
func (s *YARAScanner) Available() bool {
	return s.findBinary() != ""
}

// findBinary 查找 yr 路径：优先插件目录 → 系统 PATH
func (s *YARAScanner) findBinary() string {
	// 1. 插件工作目录下的 bin/yr
	if pluginDir := os.Getenv("PLUGIN_DIR"); pluginDir != "" {
		local := filepath.Join(pluginDir, "bin", "yr")
		if _, err := os.Stat(local); err == nil {
			return local
		}
	}
	// 2. 系统 PATH
	if p, err := exec.LookPath(yaraBinary); err == nil {
		return p
	}
	return ""
}

// yaraMatch YARA-X JSON 输出结构
type yaraMatch struct {
	Path  string `json:"path"`
	Rules []struct {
		Identifier string   `json:"identifier"`
		Namespace  string   `json:"namespace"`
		Tags       []string `json:"tags,omitempty"`
		Metadata   []struct {
			Identifier string      `json:"identifier"`
			Value      interface{} `json:"value"`
		} `json:"metadata,omitempty"`
	} `json:"rules"`
}

// Scan 使用 YARA-X 扫描指定路径
func (s *YARAScanner) Scan(ctx context.Context, paths []string) ([]ScanResult, error) {
	if !s.Available() {
		s.logger.Warn("yr (YARA-X) 不可用，跳过 YARA 扫描")
		return nil, nil
	}

	var results []ScanResult

	for _, scanPath := range paths {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		pathResults, err := s.scanPath(ctx, scanPath)
		if err != nil {
			s.logger.Error("YARA 扫描路径失败",
				zap.String("path", scanPath),
				zap.Error(err))
			continue
		}
		results = append(results, pathResults...)
	}

	return results, nil
}

// scanPath 使用 YARA-X 扫描单个路径
func (s *YARAScanner) scanPath(ctx context.Context, scanPath string) ([]ScanResult, error) {
	// yr scan -r --output-format=json RULES_DIR TARGET
	args := []string{
		"scan",
		"-r",
		"--output-format=json",
		s.rulesDir,
		scanPath,
	}

	cmd := exec.CommandContext(ctx, s.findBinary(), args...)
	output, err := cmd.Output()
	if err != nil {
		// yr 返回非零退出码可能表示匹配或错误
		if exitErr, ok := err.(*exec.ExitError); ok {
			// 如果有 stdout 输出，说明有匹配结果
			if len(output) > 0 {
				s.logger.Debug("YARA 扫描发现匹配", zap.Int("exit_code", exitErr.ExitCode()))
			} else {
				return nil, fmt.Errorf("yr 执行错误 (exit %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
			}
		} else {
			return nil, fmt.Errorf("yr 执行失败: %w", err)
		}
	}

	return s.parseOutput(output)
}

// parseOutput 解析 YARA-X JSON 输出
func (s *YARAScanner) parseOutput(output []byte) ([]ScanResult, error) {
	if len(output) == 0 {
		return nil, nil
	}

	var results []ScanResult

	// YARA-X JSON 输出是换行分隔的 JSON 对象
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var match yaraMatch
		if err := json.Unmarshal([]byte(line), &match); err != nil {
			s.logger.Warn("解析 YARA 输出失败", zap.String("line", line), zap.Error(err))
			continue
		}

		for _, rule := range match.Rules {
			threatType := s.extractThreatType(rule.Tags, rule.Metadata)
			severity := s.extractSeverity(rule.Metadata, threatType)

			result := ScanResult{
				FilePath:   match.Path,
				ThreatName: rule.Identifier,
				ThreatType: threatType,
				Severity:   severity,
				Engine:     "yara",
				RuleName:   rule.Identifier,
				DetectedAt: time.Now(),
			}

			result.FileHash, result.FileSize = getFileInfo(match.Path)
			results = append(results, result)
		}
	}

	return results, nil
}

// extractThreatType 从 YARA 规则标签和元数据提取威胁类型
func (s *YARAScanner) extractThreatType(tags []string, metadata []struct {
	Identifier string      `json:"identifier"`
	Value      interface{} `json:"value"`
}) string {
	// 先检查标签
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		switch {
		case lower == "ransomware":
			return "ransomware"
		case lower == "rootkit":
			return "rootkit"
		case lower == "backdoor":
			return "backdoor"
		case lower == "trojan":
			return "trojan"
		case lower == "miner" || lower == "coinminer":
			return "miner"
		case lower == "worm":
			return "worm"
		case lower == "virus":
			return "virus"
		}
	}

	// 检查元数据中的 threat_type
	for _, m := range metadata {
		if m.Identifier == "threat_type" {
			if v, ok := m.Value.(string); ok {
				return v
			}
		}
	}

	return "other"
}

// extractSeverity 从元数据提取严重级别
func (s *YARAScanner) extractSeverity(metadata []struct {
	Identifier string      `json:"identifier"`
	Value      interface{} `json:"value"`
}, threatType string) string {
	for _, m := range metadata {
		if m.Identifier == "severity" {
			if v, ok := m.Value.(string); ok {
				return v
			}
		}
	}
	return getSeverity(threatType)
}
