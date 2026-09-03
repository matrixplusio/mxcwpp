package biz

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	vulnCacheTTL = 7 * 24 * time.Hour // 缓存有效期 7 天
)

// VulnCacheMode 漏洞库模式
type VulnCacheMode string

const (
	CacheModeOnline  VulnCacheMode = "online"  // 在线模式
	CacheModeOffline VulnCacheMode = "offline" // 离线模式
	CacheModeHybrid  VulnCacheMode = "hybrid"  // 混合模式（默认）
)

// VulnCacheManager 离线漏洞库缓存管理器
type VulnCacheManager struct {
	db     *gorm.DB
	logger *zap.Logger
	mode   VulnCacheMode
}

// NewVulnCacheManager 创建缓存管理器
func NewVulnCacheManager(db *gorm.DB, logger *zap.Logger) *VulnCacheManager {
	return &VulnCacheManager{
		db:     db,
		logger: logger,
		mode:   CacheModeHybrid,
	}
}

// GetMode 获取当前缓存模式
func (c *VulnCacheManager) GetMode() VulnCacheMode {
	return c.mode
}

// SetMode 设置缓存模式
func (c *VulnCacheManager) SetMode(mode VulnCacheMode) {
	c.mode = mode
}

// GetCachedVuln 从缓存中获取漏洞数据（仅返回未过期的）
// 返回 nil 表示缓存未命中
func (c *VulnCacheManager) GetCachedVuln(osvID string) (json.RawMessage, error) {
	var cache model.VulnCache
	err := c.db.Where("osv_id = ? AND expired_at > ?", osvID, time.Now()).
		First(&cache).Error
	if err != nil {
		return nil, err
	}
	return json.RawMessage(cache.RawJSON), nil
}

// GetCachedVulnIncludeExpired 从缓存中获取漏洞数据（包含过期数据，用于 API 不可用时兜底）
func (c *VulnCacheManager) GetCachedVulnIncludeExpired(osvID string) (json.RawMessage, error) {
	var cache model.VulnCache
	err := c.db.Where("osv_id = ?", osvID).First(&cache).Error
	if err != nil {
		return nil, err
	}
	return json.RawMessage(cache.RawJSON), nil
}

// PutCache 写入缓存
func (c *VulnCacheManager) PutCache(osvID string, rawJSON []byte) error {
	now := model.Now()
	expiredAt := model.ToLocalTime(time.Now().Add(vulnCacheTTL))

	cache := model.VulnCache{
		OsvID:     osvID,
		RawJSON:   string(rawJSON),
		CachedAt:  now,
		ExpiredAt: expiredAt,
	}

	// upsert：存在则更新，不存在则插入
	return c.db.Where("osv_id = ?", osvID).
		Assign(map[string]any{
			"raw_json":   string(rawJSON),
			"cached_at":  now,
			"expired_at": expiredAt,
		}).
		FirstOrCreate(&cache).Error
}

// GetStats 获取漏洞库统计信息（基于 vulnerabilities 表）
func (c *VulnCacheManager) GetStats() (*CacheStats, error) {
	stats := &CacheStats{
		Mode: string(c.mode),
	}

	var result struct {
		Total       int64      `gorm:"column:total"`
		Unpatched   int64      `gorm:"column:unpatched"`
		Patched     int64      `gorm:"column:patched"`
		LastUpdated *time.Time `gorm:"column:last_updated"`
	}
	c.db.Model(&model.Vulnerability{}).Select(
		"COUNT(*) as total, " +
			"SUM(CASE WHEN status != 'patched' THEN 1 ELSE 0 END) as unpatched, " +
			"SUM(CASE WHEN status = 'patched' THEN 1 ELSE 0 END) as patched, " +
			"MAX(updated_at) as last_updated",
	).Scan(&result)

	stats.TotalCount = result.Total
	stats.UnpatchedCount = result.Unpatched
	stats.PatchedCount = result.Patched
	if result.LastUpdated != nil {
		lt := model.ToLocalTime(*result.LastUpdated)
		stats.LastUpdated = &lt
	}

	return stats, nil
}

// CacheStats 漏洞库统计
type CacheStats struct {
	Mode           string           `json:"mode"`
	TotalCount     int64            `json:"totalCount"`
	UnpatchedCount int64            `json:"unpatchedCount"`
	PatchedCount   int64            `json:"patchedCount"`
	LastUpdated    *model.LocalTime `json:"lastUpdated"`
}

// PurgeExpired 清理过期缓存
func (c *VulnCacheManager) PurgeExpired() (int64, error) {
	result := c.db.Where("expired_at < ?", time.Now()).Delete(&model.VulnCache{})
	if result.Error != nil {
		return 0, result.Error
	}
	c.logger.Info("清理过期漏洞缓存", zap.Int64("purged", result.RowsAffected))
	return result.RowsAffected, nil
}

// ImportOfflineDB 导入离线 OSV 数据包（zip 格式）
func (c *VulnCacheManager) ImportOfflineDB(filePath string) (*model.VulnDBImport, error) {
	c.logger.Info("开始导入离线漏洞库", zap.String("file", filePath))

	// 计算文件信息
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("文件不存在: %w", err)
	}

	hash, err := hashFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("计算文件哈希失败: %w", err)
	}

	// 创建导入记录
	record := &model.VulnDBImport{
		FileName: filepath.Base(filePath),
		FileSize: fileInfo.Size(),
		SHA256:   hash,
		Status:   "importing",
	}
	c.db.Create(record)

	// 解压并导入
	count, err := c.importZip(filePath)
	if err != nil {
		record.Status = "failed"
		c.db.Save(record)
		return record, fmt.Errorf("导入失败: %w", err)
	}

	record.VulnCount = count
	record.Status = "success"
	c.db.Save(record)

	c.logger.Info("离线漏洞库导入完成",
		zap.String("file", record.FileName),
		zap.Int("count", count))
	return record, nil
}

// importZip 解压 OSV 数据包并写入缓存
func (c *VulnCacheManager) importZip(filePath string) (int, error) {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return 0, fmt.Errorf("打开 zip 文件失败: %w", err)
	}
	defer r.Close()

	count := 0
	now := model.Now()
	expiredAt := model.ToLocalTime(time.Now().Add(vulnCacheTTL))

	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			c.logger.Warn("打开 zip 内文件失败", zap.String("name", f.Name), zap.Error(err))
			continue
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		// 提取 OSV ID（从文件名或 JSON 内容）
		osvID := strings.TrimSuffix(filepath.Base(f.Name), ".json")
		if osvID == "" {
			continue
		}

		cache := model.VulnCache{
			OsvID:     osvID,
			RawJSON:   string(data),
			CachedAt:  now,
			ExpiredAt: expiredAt,
		}
		c.db.Where("osv_id = ?", osvID).
			Assign(map[string]any{
				"raw_json":   string(data),
				"cached_at":  now,
				"expired_at": expiredAt,
			}).
			FirstOrCreate(&cache)
		count++
	}

	return count, nil
}

// GetImportHistory 获取导入历史
func (c *VulnCacheManager) GetImportHistory(page, pageSize int) ([]model.VulnDBImport, int64, error) {
	var total int64
	c.db.Model(&model.VulnDBImport{}).Count(&total)

	var records []model.VulnDBImport
	err := c.db.Order("imported_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&records).Error

	return records, total, err
}

// hashFile 计算文件 SHA256
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
