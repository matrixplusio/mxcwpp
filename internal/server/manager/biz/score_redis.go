// Package biz 提供业务逻辑层（Redis 缓存实现）
package biz

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// RedisClient Redis 客户端接口（用于依赖注入和测试）
type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value any, expiration time.Duration) error
	Del(ctx context.Context, keys ...string) error
	Exists(ctx context.Context, key string) (bool, error)
}

// BaselineScoreCacheRedis 使用 Redis 的基线得分缓存
type BaselineScoreCacheRedis struct {
	db          *gorm.DB
	logger      *zap.Logger
	redisClient RedisClient
	ttl         time.Duration
	keyPrefix   string
}

// NewBaselineScoreCacheRedis 创建使用 Redis 的基线得分缓存
func NewBaselineScoreCacheRedis(db *gorm.DB, logger *zap.Logger, redisClient RedisClient, ttl time.Duration) *BaselineScoreCacheRedis {
	return &BaselineScoreCacheRedis{
		db:          db,
		logger:      logger,
		redisClient: redisClient,
		ttl:         ttl,
		keyPrefix:   "baseline:score:",
	}
}

// GetHostScore 获取主机得分（带 Redis 缓存）
func (c *BaselineScoreCacheRedis) GetHostScore(ctx context.Context, hostID string) (*HostScore, error) {
	cacheKey := c.keyPrefix + hostID

	// 先查 Redis 缓存
	cached, err := c.redisClient.Get(ctx, cacheKey)
	if err == nil && cached != "" {
		var score HostScore
		if err := json.Unmarshal([]byte(cached), &score); err == nil {
			c.logger.Debug("从 Redis 缓存获取主机得分",
				zap.String("host_id", hostID),
				zap.Int("score", score.BaselineScore),
			)
			return &score, nil
		}
		c.logger.Warn("Redis 缓存数据解析失败", zap.Error(err), zap.String("host_id", hostID))
	}

	// 缓存未命中，重新计算
	score, err := c.calculateHostScore(hostID)
	if err != nil {
		return nil, err
	}

	// 写入 Redis 缓存
	scoreJSON, err := json.Marshal(score)
	if err == nil {
		if err := c.redisClient.Set(ctx, cacheKey, string(scoreJSON), c.ttl); err != nil {
			c.logger.Warn("写入 Redis 缓存失败", zap.Error(err), zap.String("host_id", hostID))
		} else {
			c.logger.Debug("主机得分已写入 Redis 缓存",
				zap.String("host_id", hostID),
				zap.Int("score", score.BaselineScore),
			)
		}
	}

	return score, nil
}

// calculateHostScore 计算主机得分（与内存缓存版本相同）
func (c *BaselineScoreCacheRedis) calculateHostScore(hostID string) (*HostScore, error) {
	// 查询主机最新的检测结果（按规则分组，取最新的）
	var latestResults []struct {
		RuleID   string
		Status   string
		Severity string
	}

	// 使用优化的查询（与内存缓存版本相同）
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

	if err := c.db.Raw(rawSQL, hostID).Scan(&latestResults).Error; err != nil {
		// 回退到子查询方式
		c.logger.Debug("窗口函数查询失败，使用子查询方式", zap.Error(err))

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
func (c *BaselineScoreCacheRedis) InvalidateHostScore(ctx context.Context, hostID string) error {
	cacheKey := c.keyPrefix + hostID
	return c.redisClient.Del(ctx, cacheKey)
}

// InvalidateAllScores 使所有主机得分缓存失效（谨慎使用）
func (c *BaselineScoreCacheRedis) InvalidateAllScores(ctx context.Context) error {
	// 注意：实际实现中需要使用 Redis SCAN 命令遍历所有匹配的 key
	// 这里提供一个占位实现
	c.logger.Warn("InvalidateAllScores 需要实现 Redis SCAN 逻辑")
	return fmt.Errorf("not implemented: 需要使用 Redis SCAN 命令")
}
