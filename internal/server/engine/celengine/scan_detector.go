// Package celengine 的端口扫描检测器
// 使用 Redis 滑动窗口统计同一源 IP 在时间窗口内访问的不同端口数
// 超过阈值时生成告警
package celengine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
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

	// scanCampaignWindow 判定"同一来源跨资产扫描"的回看窗口。
	//
	// 单台主机上的一次扫描按端口数定级，多半只是 medium；但同一个外部来源在一天内
	// 扫了不止一台，就不再是背景噪声而是对着我们的暴露面在摸——这个信号只有把各主机
	// 的命中合起来才看得见，单条告警各自为政时会被当成普通扫描关掉。
	scanCampaignWindow = 24 * time.Hour
	// scanCampaignPrefix 记录某外部来源在窗口内触发过扫描告警的主机集合。
	scanCampaignPrefix = "scan:campaign:"
	// scanReturnWindow / scanReturnPrefix 记录某外部来源触发扫描告警的日期，用于识别隔日回访。
	scanReturnWindow = 30 * 24 * time.Hour
	scanReturnPrefix = "scan:days:"
	// scanCampaignRuleID 跨资产扫描告警的规则 ID，与单主机的 scan-detector 区分，便于单独订阅通知。
	scanCampaignRuleID = "scan-campaign"
)

// ScanDetector 端口扫描检测器
type ScanDetector struct {
	rdb    *redis.Client
	db     *gorm.DB
	logger *zap.Logger

	// 源 IP 白名单缓存（从 alert_whitelists 表 source_ip_cidr 字段加载）
	whitelistMu    sync.RWMutex
	whitelistCIDRs []*net.IPNet

	// onAlert 每新开一条扫描类告警时调用，供上层按检测阶段计数；为空时不计。
	onAlert func(stage, ruleID, severity string)
}

// SetAlertObserver 注入「新开告警」回调。须在开始处理事件之前设置。
func (d *ScanDetector) SetAlertObserver(fn func(stage, ruleID, severity string)) {
	if d != nil {
		d.onAlert = fn
	}
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

// reloadWhitelist 从 alert_whitelists 表加载 source_ip_cidr 非空、且此刻生效的记录。
// 解析失败的 CIDR 写 warn 但不影响其他条目。
//
// 与 CEL 路径不同，这里命中即跳过、不记 suppressed 告警：扫描判定要先对每个入站连接
// 在 Redis 里计数，白名单网段（如节点健康探测）的连接量很大，让它们进计数会显著加重
// 热路径负担。过期与停用照常生效。
func (d *ScanDetector) reloadWhitelist() {
	var rows []model.AlertWhitelist
	if err := d.db.Select("id, source_ip_cidr, enabled, expires_at").
		Where("source_ip_cidr <> ''").
		Find(&rows).Error; err != nil {
		d.logger.Warn("加载 ScanDetector 源 IP 白名单失败", zap.Error(err))
		return
	}
	cidrs := make([]*net.IPNet, 0, len(rows))
	bad := 0
	now := time.Now()
	for _, r := range rows {
		if !r.Active(now) {
			continue
		}
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
// 服务」——对外网源，这就是针对暴露面的探测；
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
	// （如托管 K8s 节点池健康探测、集群内部端口扫描工具等）
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

// persistScanAlert 把一次扫描命中落到 host+源 IP 分组，返回是否新开了一条告警。
func (d *ScanDetector) persistScanAlert(alert model.Alert, now model.LocalTime) (bool, error) {
	created, err := model.UpsertGroupedAlert(d.db, alert.ResultID, func() model.Alert {
		return alert
	}, func(existing *model.Alert) error {
		updates := map[string]any{
			"last_seen_at": now,
			"hit_count":    gorm.Expr("hit_count + 1"),
			"description":  alert.Description,
		}
		// 级别只升不降：跨资产或回访把它升上去之后，窗口过了的下一次命中不该把它降回 medium。
		if scanSeverityRank(alert.Severity) > scanSeverityRank(existing.Severity) {
			updates["severity"] = alert.Severity
		}
		return d.db.Model(existing).Updates(updates).Error
	})
	return created != nil, err
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

	severity := d.classifySeverity(portCount, remoteAddr)
	var campaignHosts []string
	if !internal {
		// 跨资产与回访只对外网源判定：内网源的多主机探测是监控与网格的常态。
		campaignHosts = d.recordCampaignHost(ctx, remoteAddr, hostID)
		returning := d.recordScanDay(ctx, remoteAddr, time.Now())
		if len(campaignHosts) >= 2 {
			severity = "critical"
		} else if returning {
			severity = bumpSeverity(severity)
		}
	}

	alert := model.Alert{
		ResultID:       resultID,
		HostID:         hostID,
		RuleID:         "scan-detector",
		Source:         model.AlertSourceDetection,
		Severity:       severity,
		Category:       "port_scan",
		ATTCKTechnique: "T1046",                      // Network Service Discovery
		ATTCKTactic:    tacticFromTechnique("T1046"), // TA0007 Discovery
		Title:          fmt.Sprintf("端口扫描检测 - 来自 %s", remoteAddr),
		Description:    fmt.Sprintf("在 %d 秒内检测到来自 %s 的 %d 个不同端口访问，疑似端口扫描行为。被扫描端口：%s", int(scanWindow.Seconds()), remoteAddr, portCount, portsStr),
		Status:         model.AlertStatusActive,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}
	if internal {
		// 内网源多为节点/监控探测：记一条通知时间，统一出口就不会把它当未通知告警推出去
		alert.LastNotifiedAt = &now
	}

	// 同一 host+源 IP 的重复扫描并进组内仍开着的告警、累加 hit_count；
	// 那条告警被关闭后，再来的扫描生成复发告警，不改写已定案的记录。
	//
	// 冷却只挡住 5 分钟内的重复，持续扫描每过一个冷却窗就再触发一次。
	// 端口列表随每轮变化，所以 description 也要跟着刷新，否则详情停在第一次命中。
	created, err := d.persistScanAlert(alert, now)
	if err != nil {
		d.logger.Error("创建端口扫描告警失败", zap.Error(err))
		return
	}
	if created && d.onAlert != nil {
		d.onAlert("scan", alert.RuleID, alert.Severity)
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

	// 外网源的新告警由 manager 统一出口从告警表桥接通知；并进已开告警的命中不再通知。

	if len(campaignHosts) >= 2 {
		d.raiseCampaignAlert(remoteAddr, campaignHosts, now)
	}
}

// recordCampaignHost 记下该外部来源在本主机触发了扫描告警，返回窗口内它触发过的全部主机。
// Redis 出错时退回只含当前主机：宁可这一次不升级，也不因为缓存故障丢掉单主机告警。
func (d *ScanDetector) recordCampaignHost(ctx context.Context, remoteAddr, hostID string) []string {
	key := scanCampaignPrefix + remoteAddr
	pipe := d.rdb.Pipeline()
	pipe.SAdd(ctx, key, hostID)
	pipe.Expire(ctx, key, scanCampaignWindow)
	members := pipe.SMembers(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil {
		d.logger.Warn("记录跨资产扫描来源失败", zap.Error(err))
		return []string{hostID}
	}
	hosts := members.Val()
	sort.Strings(hosts)
	return hosts
}

// recordScanDay 记下该外部来源今天触发过扫描告警，返回它此前是否在别的日子触发过。
// 隔日又来，说明不是一次性路过的扫描器。
func (d *ScanDetector) recordScanDay(ctx context.Context, remoteAddr string, now time.Time) bool {
	key := scanReturnPrefix + remoteAddr
	pipe := d.rdb.Pipeline()
	pipe.SAdd(ctx, key, now.Format("20060102"))
	pipe.Expire(ctx, key, scanReturnWindow)
	card := pipe.SCard(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil {
		return false
	}
	return card.Val() >= 2
}

func scanSeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// bumpSeverity 把级别提一档，critical 封顶。
func bumpSeverity(s string) string {
	switch s {
	case "low":
		return "medium"
	case "medium":
		return "high"
	default:
		return "critical"
	}
}

// campaignAlertResultID 跨资产扫描告警按来源 IP 归一条：它描述的是"这个来源在做什么"，不属于某一台主机。
func campaignAlertResultID(remoteAddr string) string {
	return "scan-campaign-" + remoteAddr
}

// raiseCampaignAlert 为跨资产扫描生成（或刷新）一条来源级告警，并把各主机上仍开着的单主机扫描告警一并升到 critical。
//
// 告警挂在排序后的第一台主机上（保证同一来源每次落到同一台），受影响的主机写在标题与描述里。
// 单主机告警要跟着升级：研判的人多半先看到其中一条，级别停在 medium 就会被当成普通扫描放过去。
func (d *ScanDetector) raiseCampaignAlert(remoteAddr string, hostIDs []string, now model.LocalTime) {
	names := d.hostnames(hostIDs)
	desc := fmt.Sprintf("外部来源 %s 在 %d 小时内对 %d 台主机触发了端口扫描：%s。"+
		"同一来源连续扫描多台资产是针对暴露面的探测，不是背景噪声；请核对它对这些主机的访问记录，并考虑在边界封禁。",
		remoteAddr, int(scanCampaignWindow.Hours()), len(hostIDs), strings.Join(names, "、"))
	alert := model.Alert{
		ResultID:       campaignAlertResultID(remoteAddr),
		HostID:         hostIDs[0],
		RuleID:         scanCampaignRuleID,
		Source:         model.AlertSourceDetection,
		Severity:       "critical",
		Category:       "port_scan",
		ATTCKTechnique: "T1046",
		ATTCKTactic:    tacticFromTechnique("T1046"),
		Title:          fmt.Sprintf("跨资产端口扫描 - 来自 %s（%d 台主机）", remoteAddr, len(hostIDs)),
		Description:    desc,
		Status:         model.AlertStatusActive,
		FirstSeenAt:    now,
		LastSeenAt:     now,
	}
	if _, err := model.UpsertGroupedAlert(d.db, alert.ResultID, func() model.Alert {
		return alert
	}, func(existing *model.Alert) error {
		return d.db.Model(existing).Updates(map[string]any{
			"last_seen_at": now,
			"hit_count":    gorm.Expr("hit_count + 1"),
			"title":        alert.Title,
			"description":  alert.Description,
		}).Error
	}); err != nil {
		d.logger.Error("创建跨资产扫描告警失败", zap.Error(err))
		return
	}

	memberIDs := make([]string, 0, len(hostIDs))
	for _, h := range hostIDs {
		memberIDs = append(memberIDs, scanAlertResultID(h, remoteAddr))
	}
	if err := d.db.Model(&model.Alert{}).
		Where("group_key IN ? AND status = ? AND severity <> ?", memberIDs, model.AlertStatusActive, "critical").
		Update("severity", "critical").Error; err != nil {
		d.logger.Warn("升级单主机扫描告警失败", zap.Error(err))
	}
	d.logger.Warn("检测到跨资产端口扫描",
		zap.String("remote_addr", remoteAddr), zap.Int("hosts", len(hostIDs)))
}

// hostnames 把主机 ID 换成主机名用于告警文案；查不到的保留 ID。
func (d *ScanDetector) hostnames(hostIDs []string) []string {
	var rows []model.Host
	d.db.Select("host_id, hostname").Where("host_id IN ?", hostIDs).Find(&rows)
	byID := make(map[string]string, len(rows))
	for _, r := range rows {
		byID[r.HostID] = r.Hostname
	}
	out := make([]string, 0, len(hostIDs))
	for _, id := range hostIDs {
		if n := byID[id]; n != "" {
			out = append(out, n)
		} else {
			out = append(out, id)
		}
	}
	return out
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
