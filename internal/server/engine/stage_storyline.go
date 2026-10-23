package engine

import (
	"context"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/storyline"
)

// StorylineStage 把事件喂给 storyline.Engine 关联攻击链。
//
// Storyline 不直接产 Alert (它累积事件构建 story),
// 而是异步把已成熟的 story 推送到 mxcwpp.engine.storyline Topic。
// 这里 Stage.Process 返回空 Alert 数组,仅做 Ingest 副作用。
type StorylineStage struct {
	storyEngine *storyline.Engine
	logger      *zap.Logger
}

// NewStorylineStage 构造 storyline stage。
func NewStorylineStage(se *storyline.Engine, logger *zap.Logger) *StorylineStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &StorylineStage{storyEngine: se, logger: logger}
}

// Name 满足 Stage interface。
func (s *StorylineStage) Name() string { return "storyline" }

// Process 把事件喂给 storyline,无 Alert 直接返回。
//
// 故事完成时由 storyline.Engine 内部 goroutine 推 Kafka mxcwpp.engine.storyline,
// 与 Pipeline 主链解耦。
func (s *StorylineStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.storyEngine == nil {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	storyID := fields["story_id"]
	if storyID == "" {
		// 没有 story_id 的事件不参与 storyline 关联
		return nil, nil
	}
	hostname := fields["hostname"]
	s.storyEngine.Ingest(storyID, ev.HostID, hostname, ev.DataType, fields)
	return nil, nil
}

var _ Stage = (*StorylineStage)(nil)
