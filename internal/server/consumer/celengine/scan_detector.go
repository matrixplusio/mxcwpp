// Package celengine 的端口扫描检测器
// 使用 Redis 滑动窗口统计同一源 IP 在时间窗口内访问的不同端口数
// 超过阈值时生成告警
package celengine

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	// scanWindow 滑动窗口大小（60 秒内访问不同端口数）
	scanWindow = 60 * time.Second
	// scanPortThreshold 不同端口数阈值，超过此值判定为端口扫描
	scanPortThreshold = 10
	// scanKeyPrefix Redis key 前缀
	scanKeyPrefix = "scan:ports:"
	// scanAlertCooldown 同一源 IP 的告警冷却时间，避免重复告警
	scanAlertCooldown = 5 * time.Minute
	// scanCooldownPrefix Redis 冷却 key 前缀
	scanCooldownPrefix = "scan:cd:"
)

// ScanDetector 端口扫描检测器
type ScanDetector struct {
	rdb    *redis.Client
	db     *gorm.DB
	logger *zap.Logger
}

// NewScanDetector 创建端口扫描检测器
// rdb 为 nil 时不启用
func NewScanDetector(rdb *redis.Client, db *gorm.DB, logger *zap.Logger) *ScanDetector {
	if rdb == nil {
		return nil
	}
	return &ScanDetector{
		rdb:    rdb,
		db:     db,
		logger: logger,
	}
}

// CheckIncomingConnection 检查入站连接是否构成端口扫描
// hostID: 被扫描主机 ID
// remoteAddr: 扫描源 IP
// localPort: 被访问端口
// fields: 事件原始字段（用于告警详情）
func (d *ScanDetector) CheckIncomingConnection(hostID, remoteAddr, localPort string, fields map[string]string) {
	if d == nil || remoteAddr == "" || localPort == "" {
		return
	}

	ctx := context.Background()
	now := time.Now()
	windowStart := now.Add(-scanWindow)

	// Redis key: scan:ports:{hostID}:{remoteAddr}
	key := scanKeyPrefix + hostID + ":" + remoteAddr

	// 使用 sorted set：score = 时间戳(ms)，member = port
	// 同一端口只计一次（set 语义），时间戳用于窗口裁剪
	score := float64(now.UnixMilli())

	pipe := d.rdb.Pipeline()
	// 添加端口记录（如果端口已存在，更新时间戳）
	pipe.ZAdd(ctx, key, redis.Z{Score: score, Member: localPort})
	// 移除窗口外的记录
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatFloat(float64(windowStart.UnixMilli()), 'f', 0, 64))
	// 统计窗口内不同端口数
	pipe.ZCard(ctx, key)
	// 设置 key 过期（略大于窗口，防止内存泄漏）
	pipe.Expire(ctx, key, scanWindow+30*time.Second)

	results, err := pipe.Exec(ctx)
	if err != nil {
		d.logger.Error("端口扫描检测 Redis pipeline 失败", zap.Error(err))
		return
	}

	// 获取 ZCard 结果（第 3 条命令）
	cardCmd, ok := results[2].(*redis.IntCmd)
	if !ok {
		return
	}
	portCount := cardCmd.Val()

	if portCount >= scanPortThreshold {
		d.triggerScanAlert(ctx, hostID, remoteAddr, int(portCount), fields)
	}
}

// triggerScanAlert 触发端口扫描告警（带冷却去重）
func (d *ScanDetector) triggerScanAlert(ctx context.Context, hostID, remoteAddr string, portCount int, fields map[string]string) {
	// 冷却检查：同一 host+ip 在冷却期内不重复告警
	cooldownKey := scanCooldownPrefix + hostID + ":" + remoteAddr
	if d.rdb.Exists(ctx, cooldownKey).Val() > 0 {
		return
	}

	// 设置冷却标记
	d.rdb.Set(ctx, cooldownKey, "1", scanAlertCooldown)

	// 收集被扫描的端口列表
	portsKey := scanKeyPrefix + hostID + ":" + remoteAddr
	portMembers, _ := d.rdb.ZRange(ctx, portsKey, 0, -1).Result()
	portsStr := ""
	for i, p := range portMembers {
		if i > 0 {
			portsStr += ", "
		}
		portsStr += p
		if i >= 19 {
			portsStr += fmt.Sprintf(" ... (共 %d 个)", portCount)
			break
		}
	}

	now := model.ToLocalTime(time.Now())
	resultID := fmt.Sprintf("scan-%s-%s-%d", hostID, remoteAddr, time.Now().UnixNano())

	alert := model.Alert{
		ResultID:    resultID,
		HostID:      hostID,
		RuleID:      "scan-detector",
		Source:      model.AlertSourceEDR,
		Severity:    d.classifySeverity(portCount),
		Category:    "port_scan",
		Title:       fmt.Sprintf("端口扫描检测 - 来自 %s", remoteAddr),
		Description: fmt.Sprintf("在 %d 秒内检测到来自 %s 的 %d 个不同端口访问，疑似端口扫描行为。被扫描端口：%s", int(scanWindow.Seconds()), remoteAddr, portCount, portsStr),
		Status:      model.AlertStatusActive,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	if err := d.db.Create(&alert).Error; err != nil {
		d.logger.Error("创建端口扫描告警失败", zap.Error(err))
		return
	}

	d.logger.Warn("检测到端口扫描",
		zap.String("host_id", hostID),
		zap.String("remote_addr", remoteAddr),
		zap.Int("port_count", portCount),
		zap.String("ports", portsStr),
	)

	// 异步发送 EDR 告警通知
	go func() {
		var host model.Host
		hostname, ip := "", ""
		if d.db.Select("hostname, ipv4").First(&host, "host_id = ?", hostID).Error == nil {
			hostname = host.Hostname
			if len(host.IPv4) > 0 {
				ip = host.IPv4[0]
			}
		}
		ns := biz.NewNotificationService(d.db, d.logger)
		if err := ns.SendEDRAlertNotification(&biz.EDRAlertData{
			HostID:      hostID,
			Hostname:    hostname,
			IP:          ip,
			RuleName:    alert.Title,
			Severity:    alert.Severity,
			Category:    "port_scan",
			Description: alert.Description,
			DetectedAt:  time.Now(),
		}); err != nil {
			d.logger.Error("发送端口扫描告警通知失败", zap.Error(err))
		}
	}()
}

// classifySeverity 根据端口数量分级
func (d *ScanDetector) classifySeverity(portCount int) string {
	switch {
	case portCount >= 50:
		return "critical"
	case portCount >= 30:
		return "high"
	default:
		return "medium"
	}
}
