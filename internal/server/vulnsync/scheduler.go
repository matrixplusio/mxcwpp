package vulnsync

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/leader"
	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/publisher"
	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/sources"
)

// SourceSchedule 是单个数据源的调度配置。
type SourceSchedule struct {
	Name     string        // 必须与 driver.Name() 一致
	Interval time.Duration // 抓取间隔
}

// Scheduler 统一编排 Driver Registry → Publisher 推送。
//
// Leader 在线时启动 cron, 失去 leader 立即停止所有 cron。
type Scheduler struct {
	registry  *sources.Registry
	publisher *publisher.Publisher
	election  *leader.Election
	schedules []SourceSchedule
	logger    *zap.Logger

	mu      sync.Mutex
	lastRun map[string]time.Time
}

// NewScheduler 构造调度器。
func NewScheduler(reg *sources.Registry, pub *publisher.Publisher, el *leader.Election, schedules []SourceSchedule, logger *zap.Logger) *Scheduler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scheduler{
		registry:  reg,
		publisher: pub,
		election:  el,
		schedules: schedules,
		logger:    logger,
		lastRun:   make(map[string]time.Time),
	}
}

// Run 阻塞运行直到 ctx 取消。
//
// 每 30s tick 检查 leader 状态 + 各 source 是否到期需要 fetch。
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 非 leader 时不抓取 (单实例无 leader 则 election 为 nil, 视为本地 leader)
			if s.election != nil && !s.election.IsLeader() {
				continue
			}
			s.fetchDueSources(ctx)
		}
	}
}

func (s *Scheduler) fetchDueSources(ctx context.Context) {
	now := time.Now()
	for _, sch := range s.schedules {
		drv, ok := s.registry.Get(sch.Name)
		if !ok {
			s.logger.Warn("vulnsync scheduler: driver 未注册",
				zap.String("source", sch.Name))
			continue
		}

		s.mu.Lock()
		last := s.lastRun[sch.Name]
		s.mu.Unlock()

		if !last.IsZero() && now.Sub(last) < sch.Interval {
			continue // 未到期
		}

		go s.fetchOne(ctx, drv, last)

		s.mu.Lock()
		s.lastRun[sch.Name] = now
		s.mu.Unlock()
	}
}

func (s *Scheduler) fetchOne(ctx context.Context, drv sources.Driver, since time.Time) {
	name := drv.Name()
	s.logger.Info("vulnsync 开始 fetch",
		zap.String("source", name),
		zap.Time("since", since))

	res, err := drv.Fetch(ctx, since)
	if err != nil {
		s.logger.Error("vulnsync fetch 失败",
			zap.String("source", name),
			zap.Error(err))
		return
	}

	s.logger.Info("vulnsync fetch 完成",
		zap.String("source", name),
		zap.Int("advisories", len(res.Advisories)),
		zap.Int("errors", len(res.Errors)))

	if s.publisher == nil {
		return
	}

	succ, err := s.publisher.PublishBatch(ctx, res.Advisories)
	if err != nil {
		s.logger.Error("vulnsync publish 失败",
			zap.String("source", name),
			zap.Int("succeeded", succ),
			zap.Error(err))
		return
	}
	s.logger.Info("vulnsync publish 完成",
		zap.String("source", name),
		zap.Int("succeeded", succ))
}
