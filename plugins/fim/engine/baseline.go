package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

var baselineDir = "/var/lib/mxsec/fim/baselines"

// Baseline Agent 本地基线数据
type Baseline struct {
	PolicyID  string               `json:"policy_id"`
	Version   int                  `json:"version"`
	CreatedAt string               `json:"created_at"`
	Entries   map[string]FileEntry `json:"entries"`
}

// BaselineStore 本地基线文件管理
type BaselineStore struct {
	logger *zap.Logger
}

// NewBaselineStore 创建基线存储实例
func NewBaselineStore(logger *zap.Logger) *BaselineStore {
	return &BaselineStore{logger: logger}
}

// validatePolicyID 校验 PolicyID 防止路径穿越
func validatePolicyID(policyID string) error {
	if policyID == "" {
		return fmt.Errorf("空的 PolicyID")
	}
	if strings.Contains(policyID, "/") || strings.Contains(policyID, "..") || strings.Contains(policyID, "\\") {
		return fmt.Errorf("非法的 PolicyID: %s", policyID)
	}
	return nil
}

// Load 加载本地基线文件，不存在返回 nil
func (s *BaselineStore) Load(policyID string) (*Baseline, error) {
	if err := validatePolicyID(policyID); err != nil {
		return nil, err
	}
	path := filepath.Join(baselineDir, policyID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取基线文件失败: %w", err)
	}

	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, fmt.Errorf("解析基线文件失败: %w", err)
	}
	return &bl, nil
}

// Save 保存基线到本地 JSON 文件
func (s *BaselineStore) Save(bl *Baseline) error {
	if err := validatePolicyID(bl.PolicyID); err != nil {
		return err
	}
	if err := os.MkdirAll(baselineDir, 0700); err != nil {
		return fmt.Errorf("创建基线目录失败: %w", err)
	}

	data, err := json.Marshal(bl)
	if err != nil {
		return fmt.Errorf("序列化基线失败: %w", err)
	}

	path := filepath.Join(baselineDir, bl.PolicyID+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("写入基线文件失败: %w", err)
	}

	s.logger.Info("基线已保存",
		zap.String("policy_id", bl.PolicyID),
		zap.Int("version", bl.Version),
		zap.Int("entry_count", len(bl.Entries)))
	return nil
}

// NewBaseline 创建新的基线对象
func (s *BaselineStore) NewBaseline(policyID string, entries map[string]FileEntry) *Baseline {
	return &Baseline{
		PolicyID:  policyID,
		Version:   1,
		CreatedAt: time.Now().Format(time.RFC3339),
		Entries:   entries,
	}
}
