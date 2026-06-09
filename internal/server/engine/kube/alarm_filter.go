package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// notificationThrottleWindow 同指纹告警的最小通知间隔
// 首次触发立即通知，重复触发在窗口内不重复通知
const notificationThrottleWindow = time.Hour

// KubeAlarmService 告警服务,负责告警创建、白名单过滤与通知派发。
//
// 通知派发通过 AlarmNotifier interface 解耦,
// 避免 engine/kube 包反向依赖 manager/biz。
type KubeAlarmService struct {
	notifier AlarmNotifier
	db       *gorm.DB
	logger   *zap.Logger
}

// NewKubeAlarmService 创建告警服务
func NewKubeAlarmService(db *gorm.DB, logger *zap.Logger) *KubeAlarmService {
	return &KubeAlarmService{db: db, logger: logger}
}

// generateFingerprint 生成告警指纹：cluster_id|rule_id|namespace|target → SHA256 前 16 字节 hex
// 同一安全事件在不同时间触发会生成相同的指纹，用于去重
func generateFingerprint(alarm *model.KubeAlarm) string {
	raw := fmt.Sprintf("%d|%s|%s|%s",
		alarm.ClusterID, alarm.RuleID, alarm.Namespace, alarm.Target)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:16]) // 32 字符
}

// CreateAlarmWithFilter 创建告警前检查白名单，命中则跳过
// 命中同指纹 pending 告警则 UPSERT（count++、更新 last_seen_at），否则创建新告警
// 返回 (created bool, err error)：created=true 表示新建了告警行（非重复告警）
func (s *KubeAlarmService) CreateAlarmWithFilter(alarm *model.KubeAlarm) (bool, error) {
	if s.matchWhitelist(alarm) {
		s.logger.Info("告警命中白名单，已跳过",
			zap.String("alarm_type", string(alarm.AlarmType)),
			zap.String("namespace", alarm.Namespace),
			zap.String("pod_name", alarm.PodName),
			zap.Uint("cluster_id", alarm.ClusterID),
		)
		return false, nil
	}

	// 生成指纹用于去重
	alarm.Fingerprint = generateFingerprint(alarm)

	created := false
	shouldNotify := false
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var existing model.KubeAlarm
		err := tx.Where("fingerprint = ? AND status = ?",
			alarm.Fingerprint, model.KubeAlarmStatusPending).
			First(&existing).Error

		now := model.LocalTime(time.Now())

		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 未找到同指纹 pending 告警 → 创建新告警
			alarm.Count = 1
			alarm.FirstSeenAt = now
			alarm.LastSeenAt = now
			nowCopy := now
			alarm.LastNotifiedAt = &nowCopy
			if time.Time(alarm.CreatedAt).IsZero() {
				alarm.CreatedAt = now
			}
			if cerr := tx.Create(alarm).Error; cerr != nil {
				return cerr
			}
			created = true
			shouldNotify = true
			return nil
		}
		if err != nil {
			return err
		}

		// 找到同指纹 pending 告警 → UPSERT count+1 / last_seen_at
		updates := map[string]any{
			"count":        gorm.Expr("count + 1"),
			"last_seen_at": now,
			"severity":     alarm.Severity,
			"message":      alarm.Message,
			"cluster_name": alarm.ClusterName,
			"pod_name":     alarm.PodName,
			"node_name":    alarm.NodeName,
			"container_id": alarm.ContainerID,
			"image_name":   alarm.ImageName,
			"raw_data":     alarm.RawData,
		}

		// 通知限流：距上次通知超过 throttle 窗口才再次通知
		if existing.LastNotifiedAt == nil ||
			time.Since(existing.LastNotifiedAt.Time()) >= notificationThrottleWindow {
			nowCopy := now
			updates["last_notified_at"] = &nowCopy
			shouldNotify = true
		}

		if uerr := tx.Model(&model.KubeAlarm{}).
			Where("id = ?", existing.ID).
			Updates(updates).Error; uerr != nil {
			return uerr
		}
		// 回填已有 ID 到入参 alarm，方便调用侧使用
		alarm.ID = existing.ID
		alarm.Count = existing.Count + 1
		alarm.FirstSeenAt = existing.FirstSeenAt
		alarm.LastSeenAt = now
		return nil
	})

	if err != nil {
		s.logger.Error("创建/更新告警失败",
			zap.String("fingerprint", alarm.Fingerprint),
			zap.Error(err))
		return false, err
	}

	if shouldNotify {
		go s.sendAlarmNotification(alarm)
	}

	return created, nil
}

// AlarmNotifier 是 KubeAlarmService 向外发送通知的解耦接口。
// 实现方在 Manager biz 层 (NotificationService 包装),
// router 启动时注入,避免 engine/kube 循环依赖 biz。
type AlarmNotifier interface {
	NotifyKubeAlarm(alarm *model.KubeAlarm)
}

// SetNotifier 注入 notifier (启动时调用一次)。
func (s *KubeAlarmService) SetNotifier(n AlarmNotifier) {
	s.notifier = n
}

// sendAlarmNotification 异步发送 K8s 告警通知 (通过注入的 notifier)
func (s *KubeAlarmService) sendAlarmNotification(alarm *model.KubeAlarm) {
	if s.notifier == nil {
		return
	}
	s.notifier.NotifyKubeAlarm(alarm)
}

// BatchCreateAlarmsWithFilter 批量创建告警（带白名单过滤）
func (s *KubeAlarmService) BatchCreateAlarmsWithFilter(alarms []model.KubeAlarm) (created int, filtered int, err error) {
	for i := range alarms {
		ok, e := s.CreateAlarmWithFilter(&alarms[i])
		if e != nil {
			return created, filtered, e
		}
		if ok {
			created++
		} else {
			filtered++
		}
	}
	return created, filtered, nil
}

// matchWhitelist 检查告警是否命中任一白名单规则
func (s *KubeAlarmService) matchWhitelist(alarm *model.KubeAlarm) bool {
	var rules []model.KubeWhitelist
	query := s.db.Where("status = ?", model.KubeWhitelistStatusEnabled)
	if err := query.Find(&rules).Error; err != nil {
		s.logger.Error("查询白名单失败", zap.Error(err))
		return false
	}

	for _, rule := range rules {
		if s.ruleMatches(&rule, alarm) {
			// 更新命中计数（SQL 原子操作，无需事务）
			if err := s.db.Model(&rule).UpdateColumn("hit_count", gorm.Expr("hit_count + 1")).Error; err != nil {
				s.logger.Warn("更新白名单命中计数失败", zap.Uint("rule_id", rule.ID), zap.Error(err))
			}
			return true
		}
	}
	return false
}

// ruleMatches 判断单条白名单规则是否匹配告警
func (s *KubeAlarmService) ruleMatches(rule *model.KubeWhitelist, alarm *model.KubeAlarm) bool {
	// 集群匹配：rule.ClusterID 为 nil 表示全局规则
	if rule.ClusterID != nil && *rule.ClusterID != alarm.ClusterID {
		return false
	}

	// 告警类型匹配：空列表表示匹配所有类型
	if len(rule.AlarmTypes) > 0 {
		matched := false
		for _, t := range rule.AlarmTypes {
			if strings.EqualFold(t, string(alarm.AlarmType)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Namespace 匹配：空字符串表示匹配所有
	if rule.Namespace != "" && !strings.EqualFold(rule.Namespace, alarm.Namespace) {
		return false
	}

	// Pod 名称模式匹配：支持通配符 * 和正则
	if rule.PodPattern != "" && alarm.PodName != "" {
		if !matchPattern(rule.PodPattern, alarm.PodName) {
			return false
		}
	}

	return true
}

// matchPattern 支持简单通配符（*）和正则表达式匹配
func matchPattern(pattern, value string) bool {
	// 如果包含 * 但不是正则，转换为正则
	if strings.Contains(pattern, "*") && !strings.HasPrefix(pattern, "^") {
		regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
		pattern = regexPattern
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}
