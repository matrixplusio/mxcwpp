package biz

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

// AdvisoryConsumerGroupID 是 Manager 消费 mxcwpp.vuln.advisory 的 ConsumerGroup。
// 与 Engine("mxcwpp-engine")、Consumer("mxcwpp-consumer") 互不冲突，
// 同一 advisory 消息各 group 独立消费一次。
const AdvisoryConsumerGroupID = "mxcwpp-manager-vulnadvisory"

const (
	// advisoryFlushSize 累积到该条数立即 flush（size-triggered，不跑 cleanup）。
	advisoryFlushSize = 2000
	// advisoryIdleFlush 距上条消息超过该时长视为「追平」，flush 余量并跑 cleanup。
	advisoryIdleFlush = 15 * time.Second
	// advisoryHostTTL 主机软件清单缓存有效期；过期则下次 flush 前重载。
	advisoryHostTTL = 10 * time.Minute
	// advisoryCleanupMinInterval cleanup 全表扫描最小间隔，跨 partition/flush 节流。
	advisoryCleanupMinInterval = 60 * time.Second
)

// AdvisoryConsumer 消费 VulnSync 推送的富 advisory，复用 advisory.Coordinator
// 的 match + 入库写路径写 host_vulnerabilities。
//
// 取代 manager 进程内 syncCoreAdvisories 自拉路径：拉源已剥离至 VulnSync 服务，
// manager 仅消费 + 匹配。匹配/入库走 Coordinator.IngestAdvisories（与自拉路径
// 同一 mergeByConfidence/upsertVuln/bulkUpsert 代码），保证 host_vuln 集合等价。
type AdvisoryConsumer struct {
	brokers []string
	group   sarama.ConsumerGroup
	db      *gorm.DB
	coord   *advisory.Coordinator
	logger  *zap.Logger
	wg      sync.WaitGroup

	mu          sync.Mutex
	hosts       []advisory.HostSoftware
	hostsLoaded time.Time
	lastCleanup time.Time
}

// NewAdvisoryConsumer 构造 advisory ConsumerGroup。
func NewAdvisoryConsumer(brokers []string, db *gorm.DB, logger *zap.Logger) (*AdvisoryConsumer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(brokers) == 0 {
		return nil, fmt.Errorf("advisory consumer: brokers must not be empty")
	}
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V3_5_0_0
	cfg.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRoundRobin()}
	// advisory 是慢变情报，从最早 offset 起消费，确保不漏历史 advisory。
	cfg.Consumer.Offsets.Initial = sarama.OffsetOldest
	cfg.Consumer.Return.Errors = true

	group, err := sarama.NewConsumerGroup(brokers, AdvisoryConsumerGroupID, cfg)
	if err != nil {
		return nil, fmt.Errorf("advisory consumer: new consumer group: %w", err)
	}
	return &AdvisoryConsumer{
		brokers: brokers,
		group:   group,
		db:      db,
		coord:   advisory.NewCoordinator(db, logger),
		logger:  logger,
	}, nil
}

// Start 启动消费循环，ctx 取消时优雅退出。调用方应在 defer 中 Close。
func (c *AdvisoryConsumer) Start(ctx context.Context) {
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		h := &advisoryGroupHandler{c: c}
		for {
			if err := c.group.Consume(ctx, []string{kafka.TopicVulnAdvisory}, h); err != nil {
				if ctx.Err() != nil {
					return
				}
				c.logger.Error("advisory consumer group error", zap.Error(err))
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		for err := range c.group.Errors() {
			c.logger.Warn("advisory consumer group error event", zap.Error(err))
		}
	}()
	c.logger.Info("Manager advisory ConsumerGroup started",
		zap.String("group_id", AdvisoryConsumerGroupID),
		zap.String("topic", kafka.TopicVulnAdvisory),
	)
}

// Close 优雅关闭。
func (c *AdvisoryConsumer) Close() error {
	err := c.group.Close()
	c.wg.Wait()
	return err
}

// loadHostsLocked 加载/刷新主机软件清单缓存（调用方须持有 c.mu）。
//
// 与原 syncCoreAdvisories 同一查询：JOIN software 带每台在线主机的真实包清单，
// matcher 据此精确 NEVRA 比对。清单慢变，缓存 advisoryHostTTL。
func (c *AdvisoryConsumer) loadHostsLocked() {
	if !c.hostsLoaded.IsZero() && time.Since(c.hostsLoaded) < advisoryHostTTL {
		return
	}
	hosts, err := loadHostSoftware(c.db)
	if err != nil {
		c.logger.Warn("advisory consumer 加载主机清单失败，沿用旧缓存", zap.Error(err))
		return
	}
	c.hosts = hosts
	c.hostsLoaded = time.Now()
	c.logger.Info("advisory consumer 主机清单已刷新", zap.Int("host_pkg_rows", len(hosts)))
}

// flush 对累积的一批 advisory 做匹配 + 入库。
//
// runCleanup=true（idle flush，流已追平）时额外跑 host_vuln FP 清理，
// 对齐 Coordinator.Sync 末尾的清理；size-triggered flush 不跑清理（避免重复全表扫描）。
func (c *AdvisoryConsumer) flush(msgs []advisory.AdvisoryMessage, runCleanup bool) {
	if len(msgs) == 0 {
		return
	}
	c.mu.Lock()
	c.loadHostsLocked()
	hosts := c.hosts
	c.mu.Unlock()

	start := time.Now()
	vulnCount, hostVulnCount := c.coord.IngestAdvisories(msgs, hosts)
	c.logger.Info("advisory consumer flush",
		zap.Int("advisories", len(msgs)),
		zap.Int("vuln_upsert", vulnCount),
		zap.Int("host_vuln_links", hostVulnCount),
		zap.Duration("cost", time.Since(start)),
	)

	if !runCleanup {
		return
	}
	c.mu.Lock()
	due := time.Since(c.lastCleanup) >= advisoryCleanupMinInterval
	if due {
		c.lastCleanup = time.Now()
	}
	c.mu.Unlock()
	if due {
		advisory.CleanupHostVulnFP(c.db, c.logger)
		advisory.CleanupAlreadyPatched(c.db, c.logger)
	}
}

// loadHostSoftware 加载全部在线主机的真实软件包清单，供 advisory matcher 比对。
//
// JOIN software 带每条主机的包清单（NEVRA + PURL + ecosystem），否则 matcher 因
// host.PkgName="" 永不匹配 → host_vuln 全空。hosts 表无 ip 列（IP 在
// network_interfaces JSON 内），matcher 不依赖 IP，省略。
func loadHostSoftware(db *gorm.DB) ([]advisory.HostSoftware, error) {
	type hostPkgRow struct {
		HostID      string
		Hostname    string
		OSFamily    string
		OSVersion   string
		Arch        string
		PkgName     string
		PkgVer      string
		PkgEpoch    string
		PkgRelease  string
		PkgArch     string
		PURL        string
		PackageType string
	}
	var rows []hostPkgRow
	if err := db.Table("hosts h").
		Select("h.host_id, h.hostname, h.os_family, h.os_version, h.arch, s.name as pkg_name, s.version as pkg_ver, s.epoch as pkg_epoch, s.release as pkg_release, s.architecture as pkg_arch, s.purl, s.package_type").
		Joins("JOIN software s ON s.host_id = h.host_id").
		Where("h.status = ?", "online").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("加载 host+software 清单失败: %w", err)
	}
	hosts := make([]advisory.HostSoftware, 0, len(rows))
	for _, r := range rows {
		hosts = append(hosts, advisory.HostSoftware{
			HostID:       r.HostID,
			Hostname:     r.Hostname,
			OSFamily:     r.OSFamily,
			OSVer:        r.OSVersion,
			OSMajor:      extractOSMajor(r.OSVersion),
			Arch:         r.Arch,
			PkgName:      r.PkgName,
			PkgVer:       r.PkgVer,
			PkgEpoch:     r.PkgEpoch,
			PkgVerRaw:    r.PkgVer,
			PkgRelease:   r.PkgRelease,
			PkgArch:      r.PkgArch,
			PURL:         r.PURL,
			PkgEcosystem: pkgTypeToEcosystem(r.PackageType),
			PkgManager:   pkgManagerFromType(r.PackageType, r.OSFamily),
		})
	}
	return hosts, nil
}

// advisoryGroupHandler 实现 sarama.ConsumerGroupHandler，按批 + idle flush 消费。
type advisoryGroupHandler struct {
	c *AdvisoryConsumer
}

func (h *advisoryGroupHandler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *advisoryGroupHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

// ConsumeClaim 累积单 partition 消息成批，达 advisoryFlushSize 或 idle 后 flush。
//
// offset 语义：仅在 flush 成功后 MarkMessage（at-least-once）。flush 内 upsert 幂等，
// 重放不产生重复 host_vuln。
func (h *advisoryGroupHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	buf := make([]advisory.AdvisoryMessage, 0, advisoryFlushSize)
	var lastMsg *sarama.ConsumerMessage
	idle := time.NewTimer(advisoryIdleFlush)
	defer idle.Stop()

	flush := func(runCleanup bool) {
		if len(buf) == 0 {
			return
		}
		h.c.flush(buf, runCleanup)
		if lastMsg != nil {
			sess.MarkMessage(lastMsg, "")
		}
		buf = buf[:0]
		lastMsg = nil
	}

	for {
		select {
		case msg, ok := <-claim.Messages():
			if !ok {
				flush(true) // claim 关闭（rebalance/退出）：flush 余量
				return nil
			}
			m, err := advisory.UnmarshalAdvisoryMessage(msg.Value)
			if err != nil {
				h.c.logger.Warn("advisory 消息反序列化失败，跳过",
					zap.Int64("offset", msg.Offset), zap.Error(err))
				sess.MarkMessage(msg, "") // 坏消息直接跳过，不阻塞 offset
				continue
			}
			buf = append(buf, *m)
			lastMsg = msg
			if len(buf) >= advisoryFlushSize {
				flush(false)
			}
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(advisoryIdleFlush)
		case <-idle.C:
			flush(true) // 流追平：flush 余量 + 跑 cleanup
			idle.Reset(advisoryIdleFlush)
		case <-sess.Context().Done():
			flush(true)
			return nil
		}
	}
}
