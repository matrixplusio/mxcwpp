// Package biz 提供业务逻辑层
package biz

import (
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// BaselineScoreCache 基线得分缓存
type BaselineScoreCache struct {
	db     *gorm.DB
	logger *zap.Logger
	cache  map[string]*HostScore
	mu     sync.RWMutex
	ttl    time.Duration
}

// HostScore 主机得分
type HostScore struct {
	HostID        string
	BaselineScore int
	PassRate      float64
	TotalRules    int
	PassCount     int
	FailCount     int
	ErrorCount    int
	NACount       int
	CalculatedAt  time.Time
}

// NewBaselineScoreCache 创建基线得分缓存
func NewBaselineScoreCache(db *gorm.DB, logger *zap.Logger, ttl time.Duration) *BaselineScoreCache {
	cache := &BaselineScoreCache{
		db:     db,
		logger: logger,
		cache:  make(map[string]*HostScore),
		ttl:    ttl,
	}

	// 启动后台清理任务
	go cache.cleanup()

	return cache
}

// GetHostScore 获取主机得分（带缓存）
func (c *BaselineScoreCache) GetHostScore(hostID string) (*HostScore, error) {
	// 先查缓存
	c.mu.RLock()
	if score, ok := c.cache[hostID]; ok {
		if time.Since(score.CalculatedAt) < c.ttl {
			c.mu.RUnlock()
			return score, nil
		}
	}
	c.mu.RUnlock()

	// 缓存未命中或过期，重新计算
	score, err := c.calculateHostScore(hostID)
	if err != nil {
		return nil, err
	}

	// 更新缓存
	c.mu.Lock()
	c.cache[hostID] = score
	c.mu.Unlock()

	return score, nil
}

// calculateHostScore 计算主机得分
func (c *BaselineScoreCache) calculateHostScore(hostID string) (*HostScore, error) {
	// 查询主机最新的检测结果（按规则分组，取最新的）
	// 优化：使用窗口函数（如果数据库支持）或优化的子查询
	var latestResults []struct {
		RuleID   string
		Status   string
		Severity string
	}

	// 优化后的查询：使用窗口函数（MySQL 8.0+ / PostgreSQL 支持）
	// 如果数据库不支持窗口函数，回退到原来的子查询方式
	// 注意：GORM 对窗口函数支持有限，这里使用原生 SQL 优化
	rawSQL := `
		SELECT rule_id, status, severity
		FROM (
			SELECT 
				rule_id, 
				status, 
				severity,
				ROW_NUMBER() OVER (PARTITION BY rule_id ORDER BY checked_at DESC) as rn
			FROM scan_results
			WHERE host_id = ?
		) AS ranked
		WHERE rn = 1
	`

	// 尝试使用窗口函数（MySQL 8.0+ / PostgreSQL）
	if err := c.db.Raw(rawSQL, hostID).Scan(&latestResults).Error; err != nil {
		// 如果窗口函数不支持，回退到子查询方式
		c.logger.Debug("窗口函数查询失败，使用子查询方式", zap.Error(err))

		// 使用优化的子查询（利用索引）
		subQuery := c.db.Model(&model.ScanResult{}).
			Select("rule_id, MAX(checked_at) as max_checked_at").
			Where("host_id = ?", hostID).
			Group("rule_id")

		if err := c.db.Table("scan_results").
			Select("scan_results.rule_id, scan_results.status, scan_results.severity").
			Joins("INNER JOIN (?) AS latest ON scan_results.rule_id = latest.rule_id AND scan_results.checked_at = latest.max_checked_at", subQuery).
			Where("scan_results.host_id = ?", hostID).
			Find(&latestResults).Error; err != nil {
			return nil, err
		}
	}

	// 计算得分
	if len(latestResults) == 0 {
		return &HostScore{
			HostID:        hostID,
			BaselineScore: 0,
			PassRate:      0.0,
			TotalRules:    0,
			PassCount:     0,
			FailCount:     0,
			ErrorCount:    0,
			NACount:       0,
			CalculatedAt:  time.Now(),
		}, nil
	}

	// 统计
	totalRules := len(latestResults)
	passCount := 0
	failCount := 0
	errorCount := 0
	naCount := 0

	// 严重级别权重
	severityWeights := map[string]float64{
		"critical": 10.0,
		"high":     7.0,
		"medium":   4.0,
		"low":      1.0,
	}

	totalWeight := 0.0
	passWeight := 0.0

	for _, result := range latestResults {
		weight := severityWeights[result.Severity]
		if weight == 0 {
			weight = 1.0 // 默认权重
		}
		totalWeight += weight

		switch result.Status {
		case "pass":
			passCount++
			passWeight += weight
		case "fail":
			failCount++
		case "error":
			errorCount++
		case "na":
			naCount++
		}
	}

	// 计算得分（0-100）
	baselineScore := 0
	if totalWeight > 0 {
		baselineScore = int((passWeight / totalWeight) * 100.0)
	}

	// 计算通过率
	passRate := float64(passCount) / float64(totalRules)

	return &HostScore{
		HostID:        hostID,
		BaselineScore: baselineScore,
		PassRate:      passRate,
		TotalRules:    totalRules,
		PassCount:     passCount,
		FailCount:     failCount,
		ErrorCount:    errorCount,
		NACount:       naCount,
		CalculatedAt:  time.Now(),
	}, nil
}

// InvalidateHostScore 使主机得分缓存失效
func (c *BaselineScoreCache) InvalidateHostScore(hostID string) {
	c.mu.Lock()
	delete(c.cache, hostID)
	c.mu.Unlock()
}

// cleanup 清理过期缓存
func (c *BaselineScoreCache) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for hostID, score := range c.cache {
			if now.Sub(score.CalculatedAt) > c.ttl {
				delete(c.cache, hostID)
			}
		}
		c.mu.Unlock()
	}
}
