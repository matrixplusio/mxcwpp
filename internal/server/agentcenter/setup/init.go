// Package setup 提供 AgentCenter 服务的初始化逻辑
package setup

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/httptrans"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/scheduler"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/sdclient"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/server"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/service"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/transfer"
	"github.com/imkerbos/mxsec-platform/internal/server/common/kafka"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/database"
	serverLogger "github.com/imkerbos/mxsec-platform/internal/server/logger"
	"gorm.io/gorm"
)

// AgentCenterServices 包含 AgentCenter 服务所需的所有组件
type AgentCenterServices struct {
	Config                *config.Config
	Logger                *zap.Logger
	DB                    *gorm.DB
	GRPCServer            *grpc.Server
	HTTPServer            *http.Server // HTTP 管理端口（健康探测、命令下发）
	TransferService       *transfer.Service
	TaskService           *service.TaskService
	PluginUpdateScheduler *scheduler.PluginUpdateScheduler
	AgentUpdateScheduler  *scheduler.AgentUpdateScheduler
	AgentRestartScheduler *scheduler.AgentRestartScheduler
	KafkaProducer         kafka.Producer   // 可选，Kafka 未启用时为 nil
	SDClient              *sdclient.Client // 可选，manager_addr 未配置时为 nil
	StatusCtx             context.Context
	StatusCancel          context.CancelFunc
	Listener              net.Listener
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

	// 6.1 初始化 Kafka 生产者（可选）
	var kafkaProducer kafka.Producer
	if cfg.Kafka.Enabled {
		kp, err := kafka.NewAsyncProducer(cfg.Kafka, logger)
		if err != nil {
			logger.Warn("Kafka 生产者初始化失败，降级为直写 MySQL", zap.Error(err))
		} else {
			kafkaProducer = kp
			transferService.SetKafkaProducer(kp)
			logger.Info("Kafka 生产者已启用",
				zap.Strings("brokers", cfg.Kafka.Brokers),
				zap.String("topic_prefix", cfg.Kafka.TopicPrefix),
			)
		}
	}

	// 7. 创建任务服务
	taskService := service.NewTaskService(db, logger)

	ctx, cancel := context.WithCancel(context.Background())

	// 9. 创建插件更新调度器
	pluginUpdateScheduler := scheduler.NewPluginUpdateScheduler(db, transferService, logger)

	// 10. 创建 Agent 更新调度器
	agentUpdateScheduler := scheduler.NewAgentUpdateScheduler(db, transferService, cfg, logger)

	// 11. 创建 Agent 重启调度器
	agentRestartScheduler := scheduler.NewAgentRestartScheduler(db, transferService, logger)

	// 11.1 创建 SD 客户端（向 Manager 注册自身，可选）
	var sdClient *sdclient.Client
	if cfg.Server.ManagerAddr != "" {
		// 若 HTTP host 是 0.0.0.0（监听所有网卡），需要探测出口 IP 作为对外可路由地址。
		// 参考 Elkeid GetOutboundIP：向默认路由目标发 UDP，内核自动选择出口网卡，
		// 无需实际发包，适用于 Docker / K8s Pod / VM 各场景。
		advertiseIP := getOutboundIP()

		advertiseHTTPAddr := cfg.Server.HTTP.Address()
		if (cfg.Server.HTTP.Host == "0.0.0.0" || cfg.Server.HTTP.Host == "") && advertiseIP != "" {
			advertiseHTTPAddr = fmt.Sprintf("%s:%d", advertiseIP, cfg.Server.HTTP.Port)
		}

		advertiseGRPCAddr := cfg.Server.GRPC.Address()
		if (cfg.Server.GRPC.Host == "0.0.0.0" || cfg.Server.GRPC.Host == "") && advertiseIP != "" {
			advertiseGRPCAddr = fmt.Sprintf("%s:%d", advertiseIP, cfg.Server.GRPC.Port)
		}

		sdClient = sdclient.NewClient(
			cfg.Server.ManagerAddr,
			cfg.Server.InstanceID,
			advertiseGRPCAddr,
			advertiseHTTPAddr,
			transferService.GetOnlineAgentCount,
			logger,
		)
	}

	// 12. 创建网络监听器
	listener, err := net.Listen("tcp", cfg.Server.GRPC.Address())
	if err != nil {
		cancel() // 确保在错误时取消 context
		logger.Fatal("监听端口失败", zap.Error(err), zap.String("address", cfg.Server.GRPC.Address()))
		return nil, err
	}

	// 13. 构建 HTTP 管理服务器（供 Manager SD 健康探测和命令下发）
	gin.SetMode(gin.ReleaseMode)
	httpRouter := gin.New()
	httpRouter.Use(gin.Recovery())
	mgmtHandler := httptrans.NewHandler(transferService, logger)
	mgmtHandler.RegisterRoutes(httpRouter.Group("/"))
	httpRouter.GET("/metrics", gin.WrapH(promhttp.Handler()))
	httpServer := &http.Server{
		Addr:    cfg.Server.HTTP.Address(),
		Handler: httpRouter,
	}
	logger.Info("AC HTTP 管理接口已就绪", zap.String("addr", cfg.Server.HTTP.Address()))

	return &AgentCenterServices{
		Config:                cfg,
		Logger:                logger,
		DB:                    db,
		GRPCServer:            grpcServer,
		HTTPServer:            httpServer,
		TransferService:       transferService,
		TaskService:           taskService,
		PluginUpdateScheduler: pluginUpdateScheduler,
		AgentUpdateScheduler:  agentUpdateScheduler,
		AgentRestartScheduler: agentRestartScheduler,
		KafkaProducer:         kafkaProducer,
		SDClient:              sdClient,
		StatusCtx:             ctx,
		StatusCancel:          cancel,
		Listener:              listener,
	}, nil
}

// StartBackgroundServices 启动后台服务（任务调度器和状态更新器）
func (s *AgentCenterServices) StartBackgroundServices() {
	// 向 Manager SD 注册并启动心跳（非阻塞，ctx 取消时自动注销）
	if s.SDClient != nil {
		s.SDClient.Start(s.StatusCtx)
	}

	// 启动 HTTP 管理端口（非阻塞）
	if s.HTTPServer != nil {
		go func() {
			if err := s.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.Logger.Error("AC HTTP 管理服务异常退出", zap.Error(err))
			}
		}()
	}

	// 注意：任务调度（DispatchPendingTasks）已迁移至 Manager 侧（TaskScheduler + ACDispatcher）
	// AC 只保留超时检查，不再主动轮询分发，防止多 AC 实例重复下发

	// 启动任务超时调度器（检查超时任务）
	go scheduler.StartTaskTimeoutScheduler(s.DB, s.Logger)

	// 启动定期告警调度器（按配置间隔发送告警通知）
	go scheduler.StartAlertScheduler(s.DB, s.Logger)

	// 启动漏洞通报升级调度器（SLA 检查、升级通知、自动关闭）
	go scheduler.StartBulletinEscalationScheduler(s.DB, s.Logger)

	// 启动插件更新调度器（检查插件配置更新并广播）
	go s.PluginUpdateScheduler.Start(s.StatusCtx)

	// 启动 Agent 更新调度器（检查 Agent 版本更新并推送）
	go s.AgentUpdateScheduler.Start(s.StatusCtx)

	// 启动 Agent 重启调度器（检查重启记录并下发命令）
	go s.AgentRestartScheduler.Start(s.StatusCtx)

	// 启动心跳超时检测调度器（覆盖网络分区等 gRPC 未正常断开的场景）
	go scheduler.StartHeartbeatTimeoutScheduler(s.DB, s.Logger)

	// 启动插件推送超时调度器（检查卡住的推送记录并标记超时）
	go scheduler.StartPushTimeoutScheduler(s.DB, s.Logger)
}

// Cleanup 清理资源
func (s *AgentCenterServices) Cleanup() {
	if s.StatusCancel != nil {
		s.StatusCancel()
	}
	// 标记服务正在关闭，避免 unregisterConnection 将所有主机标记为离线
	if s.TransferService != nil {
		s.TransferService.GracefulShutdown()
		s.TransferService.StopMetricsBuffer()
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
	if s.HTTPServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.HTTPServer.Shutdown(ctx)
	}
	if s.KafkaProducer != nil {
		if err := s.KafkaProducer.Close(); err != nil {
			if s.Logger != nil {
				s.Logger.Error("关闭 Kafka 生产者失败", zap.Error(err))
			}
		}
	}
	if s.DB != nil {
		if err := database.Close(); err != nil {
			if s.Logger != nil {
				s.Logger.Error("关闭数据库连接失败", zap.Error(err))
			} else {
				os.Stderr.WriteString("关闭数据库连接失败: " + err.Error() + "\n")
			}
		}
	}
}

// getOutboundIP 探测本机对外可路由 IP（无需实际发包）。
// 原理：向任意外部地址发 UDP 连接，内核根据路由表选择出口网卡，从 LocalAddr 读取 IP。
// 适用于 Docker 容器、K8s Pod、VM 等各类部署场景。
func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
