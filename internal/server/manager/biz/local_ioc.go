package biz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

var sha256Re = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// normalizeIOCType 把内部值归一到 Redis set 类型(ip/hash/url/domain)
func normalizeIOCType(t string) string {
	switch strings.ToLower(t) {
	case "ip", "hash", "url", "domain":
		return strings.ToLower(t)
	default:
		return ""
	}
}

// AddLocalIOC 录入一条自有情报:落库(按 type+value 幂等)+ 立即灌入 Redis + 重导快照供 agent 匹配。
func (t *ThreatIntel) AddLocalIOC(ctx context.Context, ioc model.LocalIOC) (bool, error) {
	ioc.IOCType = normalizeIOCType(ioc.IOCType)
	ioc.Value = strings.TrimSpace(ioc.Value)
	if ioc.IOCType == "" || ioc.Value == "" {
		return false, fmt.Errorf("无效的 IOC 类型或值")
	}
	if ioc.Severity == "" {
		ioc.Severity = "high"
	}
	ioc.Enabled = true

	var existing model.LocalIOC
	err := t.db.Where("ioc_type = ? AND value = ?", ioc.IOCType, ioc.Value).First(&existing).Error
	created := false
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := t.db.Create(&ioc).Error; err != nil {
			return false, fmt.Errorf("写入本地情报失败: %w", err)
		}
		created = true
	} else if err != nil {
		return false, err
	} else if !existing.Enabled {
		t.db.Model(&existing).Update("enabled", true)
	}

	// 立即灌入 Redis(不等下次同步)+ 重导快照,让 agent 尽快匹配
	if t.redisClient != nil {
		t.redisClient.SAdd(ctx, iocRedisKeyPrefix+ioc.IOCType, ioc.Value)
		_ = t.exportSnapshot(ctx)
	}
	return created, nil
}

// loadLocalIOCsToRedis 把所有启用的自有情报灌入 Redis(每次同步调用,因 feed set 有 TTL 会过期)。
func (t *ThreatIntel) loadLocalIOCsToRedis(ctx context.Context) int {
	if t.redisClient == nil {
		return 0
	}
	var iocs []model.LocalIOC
	if err := t.db.Where("enabled = ?", true).Find(&iocs).Error; err != nil {
		t.logger.Warn("加载本地情报失败", zap.Error(err))
		return 0
	}
	byType := map[string][]any{}
	for _, i := range iocs {
		byType[i.IOCType] = append(byType[i.IOCType], i.Value)
	}
	n := 0
	for typ, vals := range byType {
		if len(vals) == 0 {
			continue
		}
		if err := t.redisClient.SAdd(ctx, iocRedisKeyPrefix+typ, vals...).Err(); err == nil {
			n += len(vals)
		}
	}
	if n > 0 {
		t.logger.Info("本地情报已合并进 IOC 集", zap.Int("count", n))
	}
	return n
}

// ListLocalIOCs 分页列出自有情报
func (t *ThreatIntel) ListLocalIOCs(iocType string, page, pageSize int) ([]model.LocalIOC, int64, error) {
	q := t.db.Model(&model.LocalIOC{})
	if it := normalizeIOCType(iocType); it != "" {
		q = q.Where("ioc_type = ?", it)
	}
	var total int64
	q.Count(&total)
	var out []model.LocalIOC
	err := q.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&out).Error
	return out, total, err
}

// DeleteLocalIOC 删除一条自有情报 + 从 Redis 移除
func (t *ThreatIntel) DeleteLocalIOC(ctx context.Context, id uint) error {
	var ioc model.LocalIOC
	if err := t.db.First(&ioc, id).Error; err != nil {
		return err
	}
	if err := t.db.Delete(&model.LocalIOC{}, id).Error; err != nil {
		return err
	}
	if t.redisClient != nil {
		t.redisClient.SRem(ctx, iocRedisKeyPrefix+ioc.IOCType, ioc.Value)
		_ = t.exportSnapshot(ctx)
	}
	return nil
}

// ConfirmThreatFromAlert 用户研判"真实威胁":解决告警 + 从命中字段提取 IOC 沉淀自有情报。
// 一处研判、全网受益:提取的外联 IP/文件 hash 进本地情报库 → 合并进 agent 匹配集。
func (t *ThreatIntel) ConfirmThreatFromAlert(ctx context.Context, alertID uint, username string) ([]model.LocalIOC, error) {
	var alert model.Alert
	if err := t.db.First(&alert, alertID).Error; err != nil {
		return nil, err
	}

	// 解决告警(标记为已处置的真实威胁)
	now := model.ToLocalTime(time.Now())
	t.db.Model(&alert).Updates(map[string]any{
		"status":         model.AlertStatusResolved,
		"resolved_at":    now,
		"resolved_by":    username,
		"resolve_reason": "用户研判:真实威胁",
	})

	// 从命中字段(actual JSON,值类型混杂)提取字符串字段
	fields := map[string]string{}
	if alert.Actual != "" {
		raw := map[string]any{}
		if json.Unmarshal([]byte(alert.Actual), &raw) == nil {
			for k, v := range raw {
				if s, ok := v.(string); ok {
					fields[k] = s
				}
			}
		}
	}
	added := t.ExtractIOCsFromFields(ctx, fields, alert.RuleID, username)
	return added, nil
}

// ExtractIOCsFromFields 从告警命中字段提取可作为情报的 IOC(外联IP + 文件hash),返回录入条数。
// 用于"确认真实威胁"研判 → 自动沉淀自有情报,一处研判全网受益。
func (t *ThreatIntel) ExtractIOCsFromFields(ctx context.Context, fields map[string]string, refID, createdBy string) []model.LocalIOC {
	var added []model.LocalIOC
	tryAdd := func(iocType, value, desc string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		ioc := model.LocalIOC{
			IOCType: iocType, Value: value, Source: "tp_extract",
			Severity: "high", Description: desc, RefType: "alert", RefID: refID, CreatedBy: createdBy,
		}
		if _, err := t.AddLocalIOC(ctx, ioc); err == nil {
			added = append(added, ioc)
		}
	}

	// 外联 IP(排除内网,内网非情报)
	if ip := fields["remote_addr"]; ip != "" {
		if pip := net.ParseIP(ip); pip != nil && !pip.IsPrivate() && !pip.IsLoopback() && !pip.IsUnspecified() {
			tryAdd("ip", ip, "研判真实威胁提取的外联 IP")
		}
	}
	// 文件 hash(sha256)
	for _, k := range []string{"sha256", "file_hash", "hash"} {
		if h := fields[k]; sha256Re.MatchString(strings.TrimSpace(h)) {
			tryAdd("hash", h, "研判真实威胁提取的文件哈希")
			break
		}
	}
	return added
}
