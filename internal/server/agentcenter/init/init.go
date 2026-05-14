// Package init 提供 AgentCenter 服务的初始化逻辑
package init

import (
	"context"
	"net"
	"os"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/scheduler"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/server"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/service"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/transfer"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/database"
	serverLogger "github.com/imkerbos/mxsec-platform/internal/server/logger"
	"gorm.io/gorm"
)

// AgentCenterServices 包含 AgentCenter 服务所需的所有组件
type AgentCenterServices struct {
	Config          *config.Config
	Logger          *zap.Logger
	DB              *gorm.DB
	GRPCServer      *grpc.Server
	TransferService *transfer.Service
	TaskService     *service.TaskService
	StatusCtx       context.Context
	StatusCancel    context.CancelFunc
	Listener        net.Listener
}

// Initialize 初始化 AgentCenter 服务的所有组件
func Initialize(configPath string) (*AgentCenterServices, error) {
	// 1. 加载配置
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	// 2. 验证配置
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// 3. 初始化日志
	logger, err := serverLogger.Init(cfg.Log)
	if err != nil {
		return nil, err
	}

	cfg.LogInfo(logger)
	logger.Info("AgentCenter 启动中...")

	// 4. 初始化数据库
	db, err := database.Init(cfg.Database, logger, cfg.Log)
	if err != nil {
		logger.Fatal("初始化数据库失败", zap.Error(err))
		return nil, err
	}

	// 5. 创建 gRPC Server
	grpcServer, err := server.CreateGRPCServer(cfg, logger)
	if err != nil {
		logger.Fatal("创建 gRPC Server 失败", zap.Error(err))
		return nil, err
	}

	// 6. 注册 Transfer 服务
	transferService := transfer.NewService(db, logger, cfg)
	grpcProto.RegisterTransferServer(grpcServer, transferService)

	// 7. 创建任务服务
	taskService := service.NewTaskService(db, logger)

	ctx, cancel := context.WithCancel(context.Background())

	// 9. 创建网络监听器
	listener, err := net.Listen("tcp", cfg.Server.GRPC.Address())
	if err != nil {
		cancel()
		logger.Fatal("监听端口失败", zap.Error(err), zap.String("address", cfg.Server.GRPC.Address()))
		return nil, err
	}

	return &AgentCenterServices{
		Config:          cfg,
		Logger:          logger,
		DB:              db,
		GRPCServer:      grpcServer,
		TransferService: transferService,
		TaskService:     taskService,
		StatusCtx:       ctx,
		StatusCancel:    cancel,
		Listener:        listener,
	}, nil
}

// StartBackgroundServices 启动后台服务（任务调度器和状态更新器）
func (s *AgentCenterServices) StartBackgroundServices() {
	// 启动任务调度器（定期分发待执行任务）
	go scheduler.StartTaskScheduler(s.TaskService, s.TransferService, s.DB, s.Logger)

}

// Cleanup 清理资源
func (s *AgentCenterServices) Cleanup() {
	if s.StatusCancel != nil {
		s.StatusCancel()
	}
	// 标记服务正在关闭，避免 unregisterConnection 将所有主机标记为离线
	if s.TransferService != nil {
		s.TransferService.GracefulShutdown()
	}
	if s.Listener != nil {
		s.Listener.Close()
	}
	if s.GRPCServer != nil {
		s.GRPCServer.GracefulStop()
	}
	if s.Logger != nil {
		s.Logger.Sync()
	}
	if s.DB != nil {
		if err := database.Close(); err != nil {
			if s.Logger != nil {
				s.Logger.Error("关闭数据库连接失败", zap.Error(err))
			} else {
				// 如果 logger 已经关闭，使用标准输出
				os.Stderr.WriteString("关闭数据库连接失败: " + err.Error() + "\n")
			}
		}
	}
}
