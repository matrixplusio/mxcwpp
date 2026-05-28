package biz

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// VulnDataSourceService 管理 vuln_data_sources 配置 + 同步状态回写。
type VulnDataSourceService struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewVulnDataSourceService 构造。
func NewVulnDataSourceService(db *gorm.DB, logger *zap.Logger) *VulnDataSourceService {
	return &VulnDataSourceService{db: db, logger: logger}
}

// IsEnabled 查 source 是否启用。不存在视为 disabled。
func (s *VulnDataSourceService) IsEnabled(name string) bool {
	var src model.VulnDataSource
	if err := s.db.Where("name = ?", name).First(&src).Error; err != nil {
		return false
	}
	return src.Enabled
}

// EnabledNames 按 category 返回启用 source 名单。空 category 返全部启用。
func (s *VulnDataSourceService) EnabledNames(category string) []string {
	var rows []model.VulnDataSource
	q := s.db.Where("enabled = ?", true)
	if category != "" {
		q = q.Where("category = ?", category)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
}

// MarkRunning 在同步开始时调用，写入 last_status='running'。
func (s *VulnDataSourceService) MarkRunning(name string) {
	now := model.LocalTime(time.Now())
	s.db.Model(&model.VulnDataSource{}).
		Where("name = ?", name).
		Updates(map[string]any{
			"last_status":  model.VulnSourceStatusRunning,
			"last_sync_at": &now,
			"last_error":   "",
		})
}

// MarkSuccess 同步成功时调用，写入 count + duration。
func (s *VulnDataSourceService) MarkSuccess(name string, count int64, duration time.Duration) {
	now := model.LocalTime(time.Now())
	s.db.Model(&model.VulnDataSource{}).
		Where("name = ?", name).
		Updates(map[string]any{
			"last_status":      model.VulnSourceStatusSuccess,
			"last_sync_at":     &now,
			"last_count":       count,
			"last_duration_ms": duration.Milliseconds(),
			"last_error":       "",
		})
}

// MarkFailed 同步失败时调用，记录 error。
func (s *VulnDataSourceService) MarkFailed(name string, err error) {
	if err == nil {
		return
	}
	now := model.LocalTime(time.Now())
	msg := err.Error()
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	s.db.Model(&model.VulnDataSource{}).
		Where("name = ?", name).
		Updates(map[string]any{
			"last_status":  model.VulnSourceStatusFailed,
			"last_sync_at": &now,
			"last_error":   msg,
		})
}

// SetEnabled 启用/禁用 source。
func (s *VulnDataSourceService) SetEnabled(id uint, enabled bool) error {
	result := s.db.Model(&model.VulnDataSource{}).
		Where("id = ?", id).
		Update("enabled", enabled)
	if result.Error != nil {
		return fmt.Errorf("更新 enabled 失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("source id=%d 不存在", id)
	}
	return nil
}

// SetBaseURL 更新 base_url（允许 admin 改镜像源）。
func (s *VulnDataSourceService) SetBaseURL(id uint, baseURL string) error {
	result := s.db.Model(&model.VulnDataSource{}).
		Where("id = ?", id).
		Update("base_url", baseURL)
	if result.Error != nil {
		return fmt.Errorf("更新 base_url 失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("source id=%d 不存在", id)
	}
	return nil
}

// Get 按 id 查单条。
func (s *VulnDataSourceService) Get(id uint) (*model.VulnDataSource, error) {
	var src model.VulnDataSource
	if err := s.db.First(&src, id).Error; err != nil {
		return nil, err
	}
	return &src, nil
}

// GetByName 按 name 查单条。
func (s *VulnDataSourceService) GetByName(name string) (*model.VulnDataSource, error) {
	var src model.VulnDataSource
	if err := s.db.Where("name = ?", name).First(&src).Error; err != nil {
		return nil, err
	}
	return &src, nil
}

// List 列全部 source。
func (s *VulnDataSourceService) List() ([]model.VulnDataSource, error) {
	var rows []model.VulnDataSource
	if err := s.db.Order("region, category, name").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}
