package scheduler

import (
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/transfer"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	iocSyncInterval = 5 * time.Minute
	iocTaskDataType = int32(9300) // DataType for IOC data push (registered in docs/datatype-allocation.md)
)

// IOCSyncScheduler periodically checks for new IOC snapshots and broadcasts
// incremental updates to all online agents via the transfer service.
type IOCSyncScheduler struct {
	db          *gorm.DB
	transferSvc *transfer.Service
	logger      *zap.Logger
	lastVersion string
}

// NewIOCSyncScheduler creates a new IOC sync scheduler.
func NewIOCSyncScheduler(db *gorm.DB, transferSvc *transfer.Service, logger *zap.Logger) *IOCSyncScheduler {
	return &IOCSyncScheduler{
		db:          db,
		transferSvc: transferSvc,
		logger:      logger,
	}
}

// Start runs the scheduler loop. It checks the latest IOC snapshot version
// every 5 minutes and broadcasts diffs (or full data) to online agents.
func (s *IOCSyncScheduler) Start(ctx context.Context) {
	s.logger.Info("IOC 同步调度器已启动", zap.Duration("interval", iocSyncInterval))

	// Run once at startup.
	s.sync()

	ticker := time.NewTicker(iocSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("IOC 同步调度器已停止")
			return
		case <-ticker.C:
			s.sync()
		}
	}
}

// PushToAgent sends the latest full IOC snapshot to a specific agent.
// Called when a new agent connects so it gets IOC data immediately.
func (s *IOCSyncScheduler) PushToAgent(agentID string) {
	var snapshot model.IOCSnapshot
	if err := s.db.Order("id DESC").First(&snapshot).Error; err != nil {
		return // No snapshot yet.
	}

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			ObjectName: "edr",
			DataType:   iocTaskDataType,
			Data:       `{"type":"full","data":` + snapshot.Data + `}`,
		}},
	}
	if err := s.transferSvc.SendCommand(agentID, cmd); err != nil {
		s.logger.Debug("推送 IOC 到新 Agent 失败",
			zap.String("agent_id", agentID),
			zap.Error(err))
	}
}

func (s *IOCSyncScheduler) sync() {
	var snapshot model.IOCSnapshot
	if err := s.db.Order("id DESC").First(&snapshot).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			s.logger.Warn("查询 IOC 快照失败", zap.Error(err))
		}
		return
	}

	if snapshot.Version == s.lastVersion {
		return // No change.
	}

	agentIDs := s.transferSvc.GetOnlineAgentIDs()
	if len(agentIDs) == 0 {
		s.lastVersion = snapshot.Version
		return
	}

	// Decide payload: incremental diff if agents have the previous version,
	// full data for first push or version jumps.
	// Since all agents receive broadcasts simultaneously, we assume they all
	// share the same version. Use diff when PrevVer matches our lastVersion.
	var payload string
	if s.lastVersion != "" && snapshot.PrevVer == s.lastVersion && snapshot.DiffAdded != "" {
		// Incremental: send diff with a wrapper indicating it's a diff.
		payload = `{"type":"diff","added":` + snapshot.DiffAdded + `,"removed":` + snapshot.DiffRemov + `}`
		s.logger.Info("广播 IOC 增量更新",
			zap.String("version", snapshot.Version),
			zap.Int("agents", len(agentIDs)))
	} else {
		// Full push: first time or version chain broken.
		payload = `{"type":"full","data":` + snapshot.Data + `}`
		s.logger.Info("广播 IOC 全量数据",
			zap.String("version", snapshot.Version),
			zap.Int("agents", len(agentIDs)),
			zap.Int("count", snapshot.Count))
	}

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			ObjectName: "edr",
			DataType:   iocTaskDataType,
			Data:       payload,
		}},
	}

	var sent int
	for _, agentID := range agentIDs {
		if err := s.transferSvc.SendCommand(agentID, cmd); err != nil {
			s.logger.Debug("推送 IOC 失败",
				zap.String("agent_id", agentID),
				zap.Error(err))
			continue
		}
		sent++
	}

	s.lastVersion = snapshot.Version
	s.logger.Info("IOC 广播完成",
		zap.String("version", snapshot.Version),
		zap.Int("sent", sent),
		zap.Int("total", len(agentIDs)))
}
