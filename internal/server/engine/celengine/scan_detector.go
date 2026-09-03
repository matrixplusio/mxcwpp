// Package celengine 的端口扫描检测器
// 使用 Redis 滑动窗口统计同一源 IP 在时间窗口内访问的不同端口数
// 超过阈值时生成告警
package celengine

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

const (
	// scanWindow 滑动窗口大小（60 秒内访问不同端口数）
	scanWindow = 60 * time.Second
	// scanPortThreshold 外网源的不同端口数阈值。
	scanPortThreshold = 10
	// scanPortThresholdInternal 内网源的阈值。
	//
	// 高得多，因为内外网的正常形态本就不同：一个服务网格节点或网关在 60 秒内
	// 连上后端十几个业务端口是常态，与"扫描"没有关系：集群节点访问网关的一批
	// 业务端口，在"不同端口数"这个维度上与一次端口扫描无法区分。
	//
	// 内网阈值仍然保留而不是直接放行：横向移动是真实存在的，扫描面通常远大于
	// 一个服务客户端会用到的端口数。
	scanPortThresholdInternal = 60
	// scanKeyPrefix Redis key 前缀
	scanKeyPrefix = "scan:ports:"
	// scanAlertCooldown 同一源 IP 的告警冷却时间，避免重复告警
	scanAlertCooldown = 5 * time.Minute
	// scanCooldownPrefix Redis 冷却 key 前缀
	scanCooldownPrefix = "scan:cd:"
	// whitelistReloadInterval 源 IP 白名单 reload 间隔
	whitelistReloadInterval = 1 * time.Minute
)

// ScanDetector 端口扫描检测器
type ScanDetector struct {
	rdb    *redis.Client
	db     *gorm.DB
	logger *zap.Logger

	// 源 IP 白名单缓存（从 alert_whitelists 表 source_ip_cidr 字段加载）
	whitelistMu    sync.RWMutex
	whitelistCIDRs []*net.IPNet
}

// NewScanDetector 创建端口扫描检测器
// rdb 为 nil 时不启用
func NewScanDetector(rdb *redis.Client, db *gorm.DB, logger *zap.Logger) *ScanDetector {
	if rdb == nil {
		return nil
	}
	d := &ScanDetector{
		rdb:    rdb,
		db:     db,
		logger: logger,
	}
	// 启动时立即加载一次，后续由 StartWhitelistReload 周期刷新
	d.reloadWhitelist()
	return d
}

// StartWhitelistReload 启动后台 goroutine 周期 reload 源 IP 白名单。
// 调用方需保证只调用一次；ctx 取消时退出。
func (d *ScanDetector) StartWhitelistReload(ctx context.Context) {
	if d == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(whitelistReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.reloadWhitelist()
			}
		}
	}()
}

// reloadWhitelist 从 alert_whitelists 表加载 source_ip_cidr 非空的记录。
// 解析失败的 CIDR 写 warn 但不影响其他条目。
func (d *ScanDetector) reloadWhitelist() {
	var rows []model.AlertWhitelist
	if err := d.db.Select("source_ip_cidr").
		Where("source_ip_cidr <> ''").
		Find(&rows).Error; err != nil {
		d.logger.Warn("加载 ScanDetector 源 IP 白名单失败", zap.Error(err))
		return
	}
	cidrs := make([]*net.IPNet, 0, len(rows))
	bad := 0
	for _, r := range rows {
		_, n, err := net.ParseCIDR(strings.TrimSpace(r.SourceIPCIDR))
		if err != nil {
			bad++
			continue
		}
		cidrs = append(cidrs, n)
	}
	d.whitelistMu.Lock()
	d.whitelistCIDRs = cidrs
	d.whitelistMu.Unlock()
	d.logger.Debug("ScanDetector 源 IP 白名单已更新",
		zap.Int("loaded", len(cidrs)),
		zap.Int("invalid", bad),
	)
}

// isSourceWhitelisted 判断源 IP 是否在白名单内。
func (d *ScanDetector) isSourceWhitelisted(remoteAddr string) bool {
	ip := net.ParseIP(strings.TrimSpace(remoteAddr))
	if ip == nil {
		return false
	}
	d.whitelistMu.RLock()
	defer d.whitelistMu.RUnlock()
	for _, n := range d.whitelistCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckIncomingConnection 检查入站连接是否构成端口扫描。
//
// 能力边界（重要）：本检测器的输入只有 tcp_accept，也就是**服务端已接受**的连接；
// Agent 不采集被拒绝的连接。因此打在未监听端口上的经典端口扫描不会产生任何事件，
// 对本检测器完全不可见。它真正能发现的是「同一来源在短时间内接触了本机大量**存活**
// 服务」——对外网源，这就是针对暴露面的探测（prod 已据此发现持续一个月的外网侦察）；
// 对内网源，这多半是服务网格或网关的正常调用，故两者阈值不同。
//
// 要覆盖真正的端口扫描，需要 Agent 侧上报连接失败事件，那是另一条链路。
// hostID: 被扫描主机 ID
// remoteAddr: 扫描源 IP
// localPort: 被访问端口
// fields: 事件原始字段（用于告警详情）
func (d *ScanDetector) CheckIncomingConnection(hostID, remoteAddr, localPort string, fields map[string]string) {
	if d == nil || remoteAddr == "" || localPort == "" {
		return
	}
	// 跳过用户在 alert_whitelists 表配置的合法扫描源
	// （如 k8s/GKE node pool 健康探测、集群内部端口扫描工具等）
	if d.isSourceWhitelisted(remoteAddr) {
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

	threshold := scanPortThreshold
	if isInternalSource(remoteAddr) {
		threshold = scanPortThresholdInternal
	}
	if int(portCount) >= threshold {
		d.triggerScanAlert(ctx, hostID, remoteAddr, int(portCount), fields)
	}
}

// scanAlertResultID 是端口扫描告警在 alerts 表中的稳定身份。
//
// 与 CEL 的 cel-{ruleID}-{hostID}、Stage 的 engine-{ruleID}-{hostID} 同构：不含时间戳。
// 源 IP 是身份的一部分——"来自 A 的扫描"和"来自 B 的扫描"是两件事，不该合并计数。
func scanAlertResultID(hostID, remoteAddr string) string {
	return fmt.Sprintf("scan-%s-%s", hostID, remoteAddr)
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
	resultID := scanAlertResultID(hostID, remoteAddr)

	internal := isInternalSource(remoteAddr)

	alert := model.Alert{
		ResultID:       resultID,
		HostID:         hostID,
		RuleID:         "scan-detector",
		Source:         model.AlertSourceDetection,
		Severity:       d.classifySeverity(portCount, remoteAddr),
		Category:       "port_scan",
		ATTCKTechnique: "T1046",                      // Network Service Discovery
		ATTCKTactic:    tacticFromTechnique("T1046"), // TA0007 Discovery
		Title:          fmt.Sprintf("端口扫描检测 - 来自 %s", remoteAddr),
		Description:    fmt.Sprintf("在 %d 秒内检测到来自 %s 的 %d 个不同端口访问，疑似端口扫描行为。被扫描端口：%s", int(scanWindow.Seconds()), remoteAddr, portCount, portsStr),
		Status:         model.AlertStatusActive,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}

	// Upsert 而非 Create：同一 host+源 IP 的重复扫描累加 hit_count，不新增行。
	//
	// 冷却只挡住 5 分钟内的重复，持续扫描每过一个冷却窗就再触发一次。此前 resultID
	// 带纳秒，每次都是新行——面对一个持续的来源会累积出数千条同义告警。
	// 端口列表随每轮变化，所以 description 也要跟着刷新，否则详情停在第一次命中。
	if err := d.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "result_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"last_seen_at": now,
			"hit_count":    gorm.Expr("hit_count + 1"),
			"description":  alert.Description,
			"severity":     alert.Severity,
			// 已处置过的告警重新命中要回到活跃态，否则复发被旧状态盖住。
			// 只复活 resolved：ignored 是人工判定的永久静音，复活它等于让降噪失效。
			"status": gorm.Expr(
				"CASE WHEN status = ? THEN ? ELSE status END",
				model.AlertStatusResolved, model.AlertStatusActive),
		}),
	}).Create(&alert).Error; err != nil {
		d.logger.Error("创建端口扫描告警失败", zap.Error(err))
		return
	}

	// 内网源多为节点/监控探测，降级 low 并以 Info 记录，避免刷 Warn 日志。
	if internal {
		d.logger.Info("检测到内网源端口探测（降级 low，未告警通知）",
			zap.String("host_id", hostID),
			zap.String("remote_addr", remoteAddr),
			zap.Int("port_count", portCount),
			zap.String("ports", portsStr),
		)
		return
	}

	d.logger.Warn("检测到端口扫描",
		zap.String("host_id", hostID),
		zap.String("remote_addr", remoteAddr),
		zap.Int("port_count", portCount),
		zap.String("ports", portsStr),
	)

	// 异步发送检测告警通知（仅外网源，内网降级项不通知以免噪声）
	go func() {
		var host model.Host
		hostname, ip := "", ""
		if d.db.Select("hostname, ipv4").First(&host, "host_id = ?", hostID).Error == nil {
			hostname = host.Hostname
			if len(host.IPv4) > 0 {
				ip = host.IPv4[0]
			}
		}
		ns := notify.NewNotificationService(d.db, d.logger)
		if err := ns.SendDetectionAlertNotification(&notify.DetectionAlertData{
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

// isInternalSource 判断源 IP 是否为内网地址（RFC1918 / 环回 / 链路本地 / IPv6 ULA）。
//
// 内网源的"端口扫描"绝大多数是基础设施正常行为：K8s 节点 kubelet 存活/就绪探测、
// Prometheus metrics 抓取、健康检查等，会在 60s 内连很多端口。这类源随节点调度/扩缩
// 动态漂移，用 IP 白名单逐个豁免追不完；而按 /24 整段消音又会让节点或 hostNetwork
// Pod 失陷后的横向扫描隐形。故内网源不消音、只降级（见 classifySeverity）——
// 既压掉日常探测噪声，又保留内网失陷主机扫描的可见性。
func isInternalSource(remoteAddr string) bool {
	ip := net.ParseIP(strings.TrimSpace(remoteAddr))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// classifySeverity 根据端口数量与源 IP 归属分级。
// 内网源降级为 low（仍入库可查，不占 active high 版面）；外网源按端口数正常分级。
func (d *ScanDetector) classifySeverity(portCount int, remoteAddr string) string {
	if isInternalSource(remoteAddr) {
		return "low"
	}
	switch {
	case portCount >= 50:
		return "critical"
	case portCount >= 30:
		return "high"
	default:
		return "medium"
	}
}
