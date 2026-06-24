package vulnsync

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/leader"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/publisher"
)

// SourceSchedule 是单个数据源的调度配置。
type SourceSchedule struct {
	Name     string        // 必须与 advisory.Source.Name() 一致
	Interval time.Duration // 抓取间隔
}

// Scheduler 统一编排 advisory.Source 拉源 → Publisher 推送富 advisory。
//
// Leader 在线时启动抓取, 失去 leader 立即停止。每个 advisory 包装成
// advisory.AdvisoryMessage 推 Kafka, 由 Manager consumer 比对主机软件清单。
type Scheduler struct {
	sources   map[string]advisory.Source // name → source
	publisher *publisher.Publisher
	election  *leader.Election
	schedules []SourceSchedule
	logger    *zap.Logger

	mu      sync.Mutex
	lastRun map[string]time.Time
}

// NewScheduler 构造调度器。sources 的 key 必须与 schedules 的 Name 对应。
func NewScheduler(srcs map[string]advisory.Source, pub *publisher.Publisher, el *leader.Election, schedules []SourceSchedule, logger *zap.Logger) *Scheduler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scheduler{
		sources:   srcs,
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

// TriggerNow 立即触发一轮全源 fetch（手动同步用），绕过调度间隔。
// 返回实际触发的 source 数；非 leader 时返回 0（由在线 leader 实际抓取）。
func (s *Scheduler) TriggerNow(ctx context.Context) int {
	if s.election != nil && !s.election.IsLeader() {
		s.logger.Warn("非 leader，跳过手动触发 fetch")
		return 0
	}
	now := time.Now()
	n := 0
	for _, sch := range s.schedules {
		src, ok := s.sources[sch.Name]
		if !ok {
			continue
		}
		s.mu.Lock()
		last := s.lastRun[sch.Name]
		s.lastRun[sch.Name] = now
		s.mu.Unlock()
		go s.fetchOne(ctx, src, last)
		n++
	}
	s.logger.Info("手动触发全源 fetch", zap.Int("sources", n))
	return n
}

func (s *Scheduler) fetchDueSources(ctx context.Context) {
	now := time.Now()
	for _, sch := range s.schedules {
		src, ok := s.sources[sch.Name]
		if !ok {
			s.logger.Warn("vulnsync scheduler: source 未注册",
				zap.String("source", sch.Name))
			continue
		}

		s.mu.Lock()
		last := s.lastRun[sch.Name]
		s.mu.Unlock()

		if !last.IsZero() && now.Sub(last) < sch.Interval {
			continue // 未到期
		}

		go s.fetchOne(ctx, src, last)

		s.mu.Lock()
		s.lastRun[sch.Name] = now
		s.mu.Unlock()
	}
}

// fetchOne 拉单源并发布。since 为零值（首跑）时各源全量拉取，
// 后续以上次抓取时刻为 watermark 增量拉取。
func (s *Scheduler) fetchOne(ctx context.Context, src advisory.Source, since time.Time) {
	name := src.Name()
	s.logger.Info("vulnsync 开始 fetch",
		zap.String("source", name),
		zap.Time("since", since))

	advs, err := src.Fetch(ctx, since)
	if err != nil {
		s.logger.Error("vulnsync fetch 失败",
			zap.String("source", name),
			zap.Error(err))
		return
	}

	conf := src.Confidence()
	msgs := make([]advisory.AdvisoryMessage, 0, len(advs))
	for _, a := range advs {
		if a == nil {
			continue
		}
		msgs = append(msgs, advisory.AdvisoryMessage{Source: name, Confidence: conf, Advisory: a})
	}

	s.logger.Info("vulnsync fetch 完成",
		zap.String("source", name),
		zap.Int("advisories", len(msgs)))

	if s.publisher == nil {
		return
	}

	succ, err := s.publisher.PublishBatch(ctx, msgs)
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
