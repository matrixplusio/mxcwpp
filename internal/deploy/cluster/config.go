package cluster

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfig 读取并校验 cluster.yaml。
func LoadConfig(path string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("解析配置路径失败: %w", err)
	}
	content, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// WriteResolvedConfig 将应用默认值后的配置写回磁盘，便于排查渲染结果。
func WriteResolvedConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("序列化 resolved cluster 配置失败: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("写入 resolved cluster 配置失败: %w", err)
	}
	return nil
}

// FindRepoRoot 从指定目录向上查找仓库根目录。
func FindRepoRoot(start string) (string, error) {
	current, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("解析路径失败: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", fmt.Errorf("未找到仓库根目录(go.mod)")
}

func expandPath(pathValue string, baseDir string) (string, error) {
	if pathValue == "" {
		return "", nil
	}
	if strings.HasPrefix(pathValue, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("解析用户目录失败: %w", err)
		}
		pathValue = filepath.Join(home, strings.TrimPrefix(pathValue, "~/"))
	}
	if filepath.IsAbs(pathValue) {
		return filepath.Clean(pathValue), nil
	}
	return filepath.Clean(filepath.Join(baseDir, pathValue)), nil
}
