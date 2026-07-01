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

// WatermarkStore 持久化各 source 的增量 watermark（上次成功拉到的时刻）。
// 用于进程重启后仍按 watermark 增量拉取，避免 since=zero 全量重拉打爆 Kafka。
// 实现由调用方注入（DB 落 vuln_data_sources.advisory_watermark）；nil 时仅内存态。
type WatermarkStore interface {
	Load(source string) (time.Time, bool)
	Save(source string, t time.Time) error
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
	store     WatermarkStore

	mu        sync.Mutex
	lastRun   map[string]time.Time // 内存态：上次「尝试」时刻，用于间隔节流
	watermark map[string]time.Time // 持久 since：上次「成功」拉到的时刻（重启从 store 载入）
}

// NewScheduler 构造调度器。sources 的 key 必须与 schedules 的 Name 对应。
// store 为 nil 时退化为纯内存态（重启后首拉全量，仅测试/无 DB 场景）。
func NewScheduler(srcs map[string]advisory.Source, pub *publisher.Publisher, el *leader.Election, schedules []SourceSchedule, logger *zap.Logger, store WatermarkStore) *Scheduler {
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &Scheduler{
		sources:   srcs,
		publisher: pub,
		election:  el,
		schedules: schedules,
		logger:    logger,
		store:     store,
		lastRun:   make(map[string]time.Time),
		watermark: make(map[string]time.Time),
	}
	// 启动时从持久层载入各 source watermark，重启后按增量拉取。
	if store != nil {
		for _, sch := range schedules {
			if wm, ok := store.Load(sch.Name); ok && !wm.IsZero() {
				s.watermark[sch.Name] = wm
				logger.Info("vulnsync 载入持久 watermark",
					zap.String("source", sch.Name), zap.Time("watermark", wm))
			}
		}
	}
	return s
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
		since := s.watermark[sch.Name]
		s.lastRun[sch.Name] = now
		s.mu.Unlock()
		go s.fetchOne(ctx, src, since, now)
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
		last := s.lastRun[sch.Name]    // 尝试节流：控制拉取间隔
		since := s.watermark[sch.Name] // 增量 since：持久 watermark
		s.mu.Unlock()

		if !last.IsZero() && now.Sub(last) < sch.Interval {
			continue // 未到期
		}

		// 先占尝试时刻（防同一 source 并发/密集重试）；watermark 仅在 fetch 成功后推进。
		s.mu.Lock()
		s.lastRun[sch.Name] = now
		s.mu.Unlock()

		go s.fetchOne(ctx, src, since, now)
	}
}

// fetchOne 拉单源并发布。since 为零值（首次、无持久 watermark）时全量拉取，
// 否则按 watermark 增量拉取。fetchStart 为本轮拉取起点，成功发布后作为新 watermark
// 持久化（仅成功推进，失败不推进，避免漏拉）。
func (s *Scheduler) fetchOne(ctx context.Context, src advisory.Source, since, fetchStart time.Time) {
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

	// 成功后推进 watermark（内存 + 持久层）：下轮/重启后按此 since 增量拉取，不再全量。
	s.mu.Lock()
	s.watermark[name] = fetchStart
	s.mu.Unlock()
	if s.store != nil {
		if err := s.store.Save(name, fetchStart); err != nil {
			s.logger.Warn("vulnsync 持久化 watermark 失败",
				zap.String("source", name), zap.Error(err))
		}
	}
}
