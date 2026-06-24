// Package rulesync 实现基于 Git 仓库的检测规则同步
// 定期从远程 Git 仓库拉取规则 YAML，增量同步到 detection_rules 表
package rulesync

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// rulesYAMLFile 规则 YAML 文件结构
type rulesYAMLFile struct {
	Rules []ruleEntry `mapstructure:"rules"`
}

type ruleEntry struct {
	Name        string   `mapstructure:"name"`
	Expression  string   `mapstructure:"expression"`
	Severity    string   `mapstructure:"severity"`
	Category    string   `mapstructure:"category"`
	MitreID     string   `mapstructure:"mitre_id"`
	DataTypes   []string `mapstructure:"data_types"`
	Description string   `mapstructure:"description"`
}

// Syncer 规则 Git 同步器
type Syncer struct {
	cfg      config.RuleSyncConfig
	db       *gorm.DB
	logger   *zap.Logger
	lastHash string // 上次同步的 commit hash
}

// New 创建规则同步器
func New(cfg config.RuleSyncConfig, db *gorm.DB, logger *zap.Logger) *Syncer {
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	if cfg.LocalDir == "" {
		cfg.LocalDir = "/var/mxcwpp/rules-repo"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Minute
	}
	return &Syncer{
		cfg:    cfg,
		db:     db,
		logger: logger,
	}
}

// Start 启动定期同步协程
func (s *Syncer) Start(ctx context.Context) {
	// 首次同步
	if err := s.Sync(); err != nil {
		s.logger.Warn("规则 Git 首次同步失败", zap.Error(err))
	}

	go func() {
		ticker := time.NewTicker(s.cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.Sync(); err != nil {
					s.logger.Warn("规则 Git 同步失败", zap.Error(err))
				}
			}
		}
	}()
}

// Sync 执行一次同步：git clone/pull → 解析 YAML → upsert DB
func (s *Syncer) Sync() error {
	// 1. 确保本地仓库存在
	if err := s.ensureRepo(); err != nil {
		return fmt.Errorf("Git 仓库操作失败: %w", err)
	}

	// 2. 检查是否有新 commit
	hash, err := s.currentHash()
	if err != nil {
		return fmt.Errorf("获取 commit hash 失败: %w", err)
	}
	if hash == s.lastHash {
		s.logger.Debug("规则仓库无变更", zap.String("hash", hash))
		return nil
	}

	// 3. 扫描并解析所有 YAML 规则文件
	rules, err := s.parseRulesDir()
	if err != nil {
		return fmt.Errorf("解析规则文件失败: %w", err)
	}

	if len(rules) == 0 {
		s.logger.Debug("规则仓库中无规则文件")
		s.lastHash = hash
		return nil
	}

	// 4. 增量同步到 DB
	imported, updated, err := s.upsertRules(rules)
	if err != nil {
		return fmt.Errorf("同步规则到 DB 失败: %w", err)
	}

	s.lastHash = hash
	s.logger.Info("规则 Git 同步完成",
		zap.String("hash", hash[:8]),
		zap.Int("parsed", len(rules)),
		zap.Int("imported", imported),
		zap.Int("updated", updated),
	)
	return nil
}

// ensureRepo clone 或 pull 远程仓库
func (s *Syncer) ensureRepo() error {
	if _, err := os.Stat(filepath.Join(s.cfg.LocalDir, ".git")); os.IsNotExist(err) {
		// Clone
		if err := os.MkdirAll(filepath.Dir(s.cfg.LocalDir), 0o755); err != nil {
			return err
		}
		return s.git("clone", "--branch", s.cfg.Branch, "--depth", "1", s.cfg.GitURL, s.cfg.LocalDir)
	}
	// Pull
	return s.gitInRepo("pull", "--ff-only")
}

// currentHash 获取当前 HEAD commit hash
func (s *Syncer) currentHash() (string, error) {
	out, err := s.gitOutput("rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// parseRulesDir 扫描本地仓库目录中的所有 YAML 规则文件
func (s *Syncer) parseRulesDir() ([]ruleEntry, error) {
	var allRules []ruleEntry

	// 支持根目录和 rules/ 子目录
	searchDirs := []string{s.cfg.LocalDir, filepath.Join(s.cfg.LocalDir, "rules")}

	for _, dir := range searchDirs {
		entries, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			continue
		}
		ymlEntries, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
		entries = append(entries, ymlEntries...)

		for _, path := range entries {
			rules, err := s.parseRuleFile(path)
			if err != nil {
				s.logger.Warn("解析规则文件失败",
					zap.String("path", path),
					zap.Error(err),
				)
				continue
			}
			allRules = append(allRules, rules...)
		}
	}

	return allRules, nil
}

// parseRuleFile 解析单个 YAML 规则文件
func (s *Syncer) parseRuleFile(path string) ([]ruleEntry, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var file rulesYAMLFile
	if err := v.Unmarshal(&file); err != nil {
		return nil, err
	}

	return file.Rules, nil
}

// upsertRules 增量同步规则到 DB（尊重 user_modified 标记）
func (s *Syncer) upsertRules(rules []ruleEntry) (imported, updated int, err error) {
	// 查询已存在的内置规则
	var existing []model.DetectionRule
	s.db.Where("builtin = ?", true).Find(&existing)
	existingMap := make(map[string]*model.DetectionRule, len(existing))
	for i := range existing {
		existingMap[existing[i].Name] = &existing[i]
	}

	for _, r := range rules {
		if r.Name == "" || r.Expression == "" {
			continue
		}

		if ex, ok := existingMap[r.Name]; ok {
			// 已存在：用户未修改过则更新
			if !ex.UserModified {
				if dbErr := s.db.Model(ex).Updates(map[string]any{
					"expression":  r.Expression,
					"severity":    r.Severity,
					"category":    r.Category,
					"mitre_id":    r.MitreID,
					"description": r.Description,
					"data_types":  model.StringArray(r.DataTypes),
				}).Error; dbErr != nil {
					s.logger.Warn("更新规则失败", zap.String("name", r.Name), zap.Error(dbErr))
					continue
				}
				updated++
			}
			continue
		}

		// 新规则：插入
		rule := model.DetectionRule{
			Name:        r.Name,
			Expression:  r.Expression,
			Severity:    r.Severity,
			Category:    r.Category,
			MitreID:     r.MitreID,
			Description: r.Description,
			DataTypes:   model.StringArray(r.DataTypes),
			Enabled:     true,
			Builtin:     true,
		}
		if dbErr := s.db.Create(&rule).Error; dbErr != nil {
			s.logger.Warn("导入规则失败", zap.String("name", r.Name), zap.Error(dbErr))
			continue
		}
		imported++
	}

	return imported, updated, nil
}

// git 执行 git 命令（不在仓库目录内）
func (s *Syncer) git(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// gitInRepo 在本地仓库目录执行 git 命令
func (s *Syncer) gitInRepo(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = s.cfg.LocalDir
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// gitOutput 在本地仓库目录执行 git 命令并返回 stdout
func (s *Syncer) gitOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = s.cfg.LocalDir
	out, err := cmd.Output()
	return string(out), err
}
