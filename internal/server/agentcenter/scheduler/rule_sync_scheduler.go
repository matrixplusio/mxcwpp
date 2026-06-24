package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/transfer"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	ruleSyncInterval = 5 * time.Minute
	ruleTaskDataType = int32(9400) // DataType for rule push (registered in docs/datatype-allocation.md)
)

// RuleSyncScheduler periodically checks for updated agent rules and broadcasts
// them to all online agents via the transfer service.
type RuleSyncScheduler struct {
	db          *gorm.DB
	transferSvc *transfer.Service
	logger      *zap.Logger
	lastVersion string // composite version: "count-maxUpdatedAt"
}

// NewRuleSyncScheduler creates a new rule sync scheduler.
func NewRuleSyncScheduler(db *gorm.DB, transferSvc *transfer.Service, logger *zap.Logger) *RuleSyncScheduler {
	return &RuleSyncScheduler{
		db:          db,
		transferSvc: transferSvc,
		logger:      logger,
	}
}

// Start runs the scheduler loop. It checks agent rules every 5 minutes
// and pushes updates to online agents when changes are detected.
func (s *RuleSyncScheduler) Start(ctx context.Context) {
	s.logger.Info("规则同步调度器已启动", zap.Duration("interval", ruleSyncInterval))

	// Run once at startup.
	s.sync()

	ticker := time.NewTicker(ruleSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("规则同步调度器已停止")
			return
		case <-ticker.C:
			s.sync()
		}
	}
}

// PushToAgent sends all enabled agent rules to a specific agent.
// Called when a new agent connects so it gets rules immediately.
func (s *RuleSyncScheduler) PushToAgent(agentID string) {
	payload, version, err := s.buildPayload()
	if err != nil || payload == "" {
		return
	}

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			ObjectName: "edr",
			DataType:   ruleTaskDataType,
			Data:       payload,
		}},
	}
	if err := s.transferSvc.SendCommand(agentID, cmd); err != nil {
		s.logger.Debug("推送规则到新 Agent 失败",
			zap.String("agent_id", agentID),
			zap.String("version", version),
			zap.Error(err))
	}
}

func (s *RuleSyncScheduler) sync() {
	version := s.computeVersion()
	if version == "" || version == s.lastVersion {
		return
	}

	agentIDs := s.transferSvc.GetOnlineAgentIDs()
	if len(agentIDs) == 0 {
		s.lastVersion = version
		return
	}

	payload, _, err := s.buildPayload()
	if err != nil {
		s.logger.Warn("构建规则推送数据失败", zap.Error(err))
		return
	}
	if payload == "" {
		s.lastVersion = version
		return
	}

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			ObjectName: "edr",
			DataType:   ruleTaskDataType,
			Data:       payload,
		}},
	}

	var sent int
	for _, agentID := range agentIDs {
		if err := s.transferSvc.SendCommand(agentID, cmd); err != nil {
			s.logger.Debug("推送规则失败",
				zap.String("agent_id", agentID),
				zap.Error(err))
			continue
		}
		sent++
	}

	s.lastVersion = version
	s.logger.Info("规则广播完成",
		zap.String("version", version),
		zap.Int("sent", sent),
		zap.Int("total", len(agentIDs)))
}

// computeVersion generates a composite version string based on rule count and latest update time.
func (s *RuleSyncScheduler) computeVersion() string {
	var count int64
	var maxUpdated time.Time

	if err := s.db.Model(&model.AgentRule{}).Where("enabled = ?", true).Count(&count).Error; err != nil {
		s.logger.Warn("查询规则数量失败", zap.Error(err))
		return ""
	}
	if count == 0 {
		return "0"
	}

	var rule model.AgentRule
	if err := s.db.Model(&model.AgentRule{}).Where("enabled = ?", true).
		Order("updated_at DESC").First(&rule).Error; err != nil {
		return ""
	}
	maxUpdated = rule.UpdatedAt.Time()

	return fmt.Sprintf("%d-%d", count, maxUpdated.Unix())
}

// buildPayload constructs the JSON payload containing all enabled agent rules.
func (s *RuleSyncScheduler) buildPayload() (string, string, error) {
	var rules []model.AgentRule
	if err := s.db.Where("enabled = ?", true).Find(&rules).Error; err != nil {
		return "", "", fmt.Errorf("查询规则失败: %w", err)
	}
	if len(rules) == 0 {
		return "", "0", nil
	}

	version := s.computeVersion()

	// Build payload: version + list of YAML rule content strings.
	type pushPayload struct {
		Version string   `json:"version"`
		Rules   []string `json:"rules"`
	}
	p := pushPayload{
		Version: version,
		Rules:   make([]string, len(rules)),
	}
	for i, r := range rules {
		p.Rules[i] = r.Content
	}

	data, err := json.Marshal(p)
	if err != nil {
		return "", "", fmt.Errorf("序列化规则数据失败: %w", err)
	}

	return string(data), version, nil
}
