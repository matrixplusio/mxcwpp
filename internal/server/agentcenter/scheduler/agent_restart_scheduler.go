package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/transfer"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// AgentRestartScheduler Agent 重启调度器
// 定期检查 DB 中的 pending 重启记录，下发重启命令并验证结果
type AgentRestartScheduler struct {
	db              *gorm.DB
	transferService *transfer.Service
	logger          *zap.Logger
	mu              sync.Mutex
}

// NewAgentRestartScheduler 创建 Agent 重启调度器
func NewAgentRestartScheduler(db *gorm.DB, transferService *transfer.Service, logger *zap.Logger) *AgentRestartScheduler {
	return &AgentRestartScheduler{
		db:              db,
		transferService: transferService,
		logger:          logger,
	}
}

// Start 启动 Agent 重启调度器
func (s *AgentRestartScheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	s.logger.Info("Agent 重启调度器已启动", zap.Duration("interval", 10*time.Second))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Agent 重启调度器已停止")
			return
		case <-ticker.C:
			s.checkAndRestart(ctx)
		}
	}
}

// checkAndRestart 检查并处理重启记录
func (s *AgentRestartScheduler) checkAndRestart(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 处理 pending 记录
	var pendingRecords []model.AgentRestartRecord
	if err := s.db.Where("status = ?", model.AgentRestartStatusPending).
		Order("created_at ASC").Find(&pendingRecords).Error; err != nil {
		s.logger.Error("查询 pending 重启记录失败", zap.Error(err))
		return
	}

	for _, record := range pendingRecords {
		s.processRestartRecord(ctx, &record)
	}

	// 验证 pushing 记录
	var pushingRecords []model.AgentRestartRecord
	if err := s.db.Where("status = ?", model.AgentRestartStatusPushing).
		Order("created_at ASC").Find(&pushingRecords).Error; err != nil {
		s.logger.Error("查询 pushing 重启记录失败", zap.Error(err))
		return
	}

	for _, record := range pushingRecords {
		s.verifyRestart(&record)
	}
}

// processRestartRecord 处理单条 pending 重启记录：下发命令
func (s *AgentRestartScheduler) processRestartRecord(ctx context.Context, record *model.AgentRestartRecord) {
	// 更新状态为 pushing，记录下发时间
	now := model.ToLocalTime(time.Now())
	s.db.Model(record).Updates(map[string]interface{}{
		"status":    model.AgentRestartStatusPushing,
		"pushed_at": &now,
	})

	// 查询目标在线主机
	var hosts []model.Host
	query := s.db.Where("status = ?", model.HostStatusOnline)
	if len(record.TargetHosts) > 0 {
		targetHostIDs := []string(record.TargetHosts)
		query = query.Where("host_id IN ?", targetHostIDs)
	}
	if err := query.Find(&hosts).Error; err != nil {
		s.logger.Error("查询目标主机失败", zap.Error(err))
		s.db.Model(record).Updates(map[string]interface{}{
			"status":  model.AgentRestartStatusFailed,
			"message": "查询目标主机失败: " + err.Error(),
		})
		return
	}

	if len(hosts) == 0 {
		completedAt := model.ToLocalTime(time.Now())
		s.db.Model(record).Updates(map[string]interface{}{
			"status":       model.AgentRestartStatusFailed,
			"message":      "没有在线的目标主机",
			"completed_at": &completedAt,
		})
		return
	}

	// 更新实际目标数
	s.db.Model(record).Update("total_count", len(hosts))

	// 向每台主机下发重启命令
	cmd := &grpcProto.Command{
		AgentRestart: true,
	}

	successCount := 0
	failedCount := 0
	var failedHostIDs []string

	for _, host := range hosts {
		if err := s.transferService.SendCommand(host.HostID, cmd); err != nil {
			s.logger.Warn("下发重启命令失败",
				zap.String("host_id", host.HostID),
				zap.Error(err))
			failedCount++
			failedHostIDs = append(failedHostIDs, host.HostID)
			continue
		}
		successCount++
	}

	// 如果全部下发失败，直接标记为 failed
	if successCount == 0 {
		completedAt := model.ToLocalTime(time.Now())
		s.db.Model(record).Updates(map[string]interface{}{
			"status":       model.AgentRestartStatusFailed,
			"failed_count": failedCount,
			"failed_hosts": model.StringArray(failedHostIDs),
			"message":      fmt.Sprintf("命令下发全部失败，失败 %d 台", failedCount),
			"completed_at": &completedAt,
		})
		return
	}

	s.db.Model(record).Updates(map[string]interface{}{
		"failed_count": failedCount,
		"failed_hosts": model.StringArray(failedHostIDs),
		"message":      fmt.Sprintf("命令已下发，成功 %d 台，失败 %d 台，等待验证重启", successCount, failedCount),
	})

	s.logger.Info("重启命令下发完成",
		zap.Uint("record_id", record.ID),
		zap.Int("success", successCount),
		zap.Int("failed", failedCount))
}

// verifyRestart 验证 pushing 状态的重启记录
func (s *AgentRestartScheduler) verifyRestart(record *model.AgentRestartRecord) {
	if record.PushedAt == nil {
		s.logger.Warn("pushing 记录缺少 pushed_at 时间", zap.Uint("record_id", record.ID))
		return
	}

	pushedAt := record.PushedAt.Time()
	elapsed := time.Since(pushedAt)

	// 查询目标主机
	var hosts []model.Host
	query := s.db.Model(&model.Host{})
	if len(record.TargetHosts) > 0 {
		targetHostIDs := []string(record.TargetHosts)
		query = query.Where("host_id IN ?", targetHostIDs)
	}
	if err := query.Find(&hosts).Error; err != nil {
		s.logger.Error("查询目标主机失败", zap.Error(err))
		return
	}

	successCount := 0
	pendingCount := 0
	var failedHostIDs []string

	// 继承之前命令下发阶段就失败的主机
	pushFailedHosts := map[string]bool{}
	for _, hid := range record.FailedHosts {
		pushFailedHosts[hid] = true
	}

	for _, host := range hosts {
		// 跳过命令下发阶段就失败的主机
		if pushFailedHosts[host.HostID] {
			continue
		}

		if host.AgentStartTime != nil && host.AgentStartTime.Time().After(pushedAt) {
			// agent_start_time 在下发时间之后 → 重启成功
			successCount++
		} else if elapsed > 2*time.Minute {
			// 超过 2 分钟未重启 → 标记失败
			failedHostIDs = append(failedHostIDs, host.HostID)
		} else {
			// 还在等待中
			pendingCount++
		}
	}

	// 合并命令下发失败的主机
	allFailedHosts := append([]string(record.FailedHosts), failedHostIDs...)
	totalFailed := len(allFailedHosts)

	// 还有主机在等待，不更新最终状态
	if pendingCount > 0 {
		s.db.Model(record).Updates(map[string]interface{}{
			"success_count": successCount,
			"failed_count":  totalFailed,
			"failed_hosts":  model.StringArray(allFailedHosts),
			"message":       fmt.Sprintf("验证中：成功 %d，失败 %d，等待 %d", successCount, totalFailed, pendingCount),
		})
		return
	}

	// 全部验证完成，确定最终状态
	completedAt := model.ToLocalTime(time.Now())
	var finalStatus model.AgentRestartStatus
	var msg string

	if totalFailed == 0 && successCount > 0 {
		finalStatus = model.AgentRestartStatusSuccess
		msg = fmt.Sprintf("重启完成，全部成功 %d 台", successCount)
	} else if successCount == 0 {
		finalStatus = model.AgentRestartStatusFailed
		msg = fmt.Sprintf("重启失败，失败 %d 台", totalFailed)
	} else {
		finalStatus = model.AgentRestartStatusPartial
		msg = fmt.Sprintf("重启部分成功，成功 %d 台，失败 %d 台", successCount, totalFailed)
	}

	s.db.Model(record).Updates(map[string]interface{}{
		"status":        finalStatus,
		"success_count": successCount,
		"failed_count":  totalFailed,
		"failed_hosts":  model.StringArray(allFailedHosts),
		"message":       msg,
		"completed_at":  &completedAt,
	})

	s.logger.Info("重启验证完成",
		zap.Uint("record_id", record.ID),
		zap.String("status", string(finalStatus)),
		zap.Int("success", successCount),
		zap.Int("failed", totalFailed))
}
