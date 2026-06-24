// Package transfer 实现 Transfer gRPC 服务
package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/metrics"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/service"
	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Connection 表示一个 Agent 连接
type Connection struct {
	AgentID   string
	Hostname  string
	IPv4      []string
	IPv6      []string
	Version   string
	LastSeen  time.Time
	stream    grpc.BidiStreamingServer[grpcProto.PackagedData, grpcProto.Command]
	ctx       context.Context
	cancel    context.CancelFunc
	sendCh    chan *grpcProto.Command
	workerSem chan struct{} // 限制异步 record 处理的并发数
	mu        sync.RWMutex
}

// GetHostname 线程安全地获取主机名
func (c *Connection) GetHostname() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Hostname
}

// GetIPv4 线程安全地获取 IPv4 地址列表（返回副本）
func (c *Connection) GetIPv4() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dst := make([]string, len(c.IPv4))
	copy(dst, c.IPv4)
	return dst
}

// GetIPv6 线程安全地获取 IPv6 地址列表（返回副本）
func (c *Connection) GetIPv6() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dst := make([]string, len(c.IPv6))
	copy(dst, c.IPv6)
	return dst
}

// GetVersion 线程安全地获取版本
func (c *Connection) GetVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Version
}

// Service 是 Transfer 服务实现
type Service struct {
	grpcProto.UnimplementedTransferServer
	db            *gorm.DB
	logger        *zap.Logger
	cfg           *config.Config
	assetService  *service.AssetService
	metricsBuffer *service.MetricsBuffer

	// Kafka 生产者（可选）：启用时 EncodedRecord 路由到 Kafka，不写 MySQL
	kafkaProducer kafka.Producer

	// 连接管理
	connections map[string]*Connection
	connMu      sync.RWMutex

	// 优雅关闭标志：Server 自身重启时跳过离线通知，避免假告警
	shutdownFlag atomic.Bool

	// P1-3: 异步通知 ctx + semaphore 限并发, 服务关闭时取消所有 dangling goroutine.
	notifyCtx    context.Context
	notifyCancel context.CancelFunc
	notifySem    chan struct{}

	// per_agent_cert 在线签发限并发：RSA-4096 keygen CPU 尖峰，500 台首装并发会打满核心。
	// 信号量把并发签发压到 ~NumCPU，多余请求排队。首次签发时 lazy init。
	signOnce sync.Once
	signSem  chan struct{}

	// 吊销序列号 set：首次查询时由 cfg.MTLS.RevokedSerials 构一次，避免每连接 O(n) 线性扫描。
	revokedOnce sync.Once
	revokedSet  map[string]struct{}
}

// initAsyncNotify P1-3: 启动时调一次, 后续 SpawnNotify 用 notifyCtx 接管 dangling goroutine.
func (s *Service) initAsyncNotify() {
	if s.notifyCtx == nil {
		s.notifyCtx, s.notifyCancel = context.WithCancel(context.Background())
		s.notifySem = make(chan struct{}, 100)
	}
}

// SpawnNotify P1-3: 接 service ctx + 限并发跑异步通知, 替代裸 go func().
// service 关闭时所有 dangling 通知统一取消.
func (s *Service) SpawnNotify(name string, fn func(ctx context.Context)) {
	s.initAsyncNotify()
	select {
	case s.notifySem <- struct{}{}:
		go func() {
			defer func() { <-s.notifySem }()
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("transfer notify panic recovered",
						zap.String("kind", name),
						zap.Any("panic", r))
				}
			}()
			fn(s.notifyCtx)
		}()
	default:
		s.logger.Warn("transfer notify queue full, drop", zap.String("kind", name))
	}
}

// CancelAsyncNotify P1-3: Shutdown 调.
func (s *Service) CancelAsyncNotify() {
	if s.notifyCancel != nil {
		s.notifyCancel()
	}
}

// SetKafkaProducer 注入 Kafka 生产者（在 AgentCenter 启动后调用）
func (s *Service) SetKafkaProducer(p kafka.Producer) {
	s.kafkaProducer = p
}

// SetClickHouse 注入 ClickHouse 连接，并启用 host_metrics CH 写入路径。
// 路径选择由 feature_flag.data_source.host_metrics 控制：
//   - "mysql"（默认）→ metrics_buffer 继续写 MySQL
//   - "ch"            → metrics_buffer 改写 CH
func (s *Service) SetClickHouse(conn chdriver.Conn) {
	if conn == nil || s.metricsBuffer == nil {
		return
	}
	target := readHostMetricsTarget(s.db, s.logger)
	s.metricsBuffer.SetClickHouse(conn, target)
	s.logger.Info("host_metrics CH 通道已配置", zap.String("target", target))
}

// readHostMetricsTarget 查 feature_flag.data_source.host_metrics → "mysql"/"ch"。
// 查询失败回落 "mysql"。
func readHostMetricsTarget(db *gorm.DB, logger *zap.Logger) string {
	var f model.FeatureFlag
	if err := db.Where("flag_key = ?", model.FlagDataSourceHostMetrics).First(&f).Error; err != nil {
		logger.Warn("host_metrics feature flag 读取失败，使用 mysql 默认", zap.Error(err))
		return "mysql"
	}
	if f.Value != "ch" {
		return "mysql"
	}
	return "ch"
}

// NewService 创建 Transfer 服务实例
func NewService(db *gorm.DB, logger *zap.Logger, cfg *config.Config) *Service {
	// 初始化资产服务
	assetService := service.NewAssetService(db, logger)

	// in-process Gauge 路径：AgentCenter 作为 Prometheus Exporter，直接暴露 /metrics 端点。
	// MySQL buffer 保留为降级路径（Prometheus 不可用时仍可查询历史数据）。
	batchSize := cfg.Metrics.MySQL.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	flushInterval := cfg.Metrics.MySQL.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}
	metricsBuffer := service.NewMetricsBuffer(db, logger, batchSize, flushInterval)
	logger.Info("监控指标存储已启用", zap.Bool("prometheus_gauge", true), zap.Bool("mysql_fallback", true))

	return &Service{
		db:            db,
		logger:        logger,
		cfg:           cfg,
		assetService:  assetService,
		metricsBuffer: metricsBuffer,
		connections:   make(map[string]*Connection),
	}
}

// Transfer 实现双向流 RPC
func (s *Service) Transfer(stream grpc.BidiStreamingServer[grpcProto.PackagedData, grpcProto.Command]) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	// 启用 Server→Agent Snappy 压缩（Agent 端已注册 snappy decompressor）
	if err := grpc.SetSendCompressor(stream.Context(), "snappy"); err != nil {
		s.logger.Warn("设置发送压缩器失败，将使用无压缩传输", zap.Error(err))
	}

	// 接收第一个 PackagedData 以获取 Agent ID
	firstData, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return status.Errorf(codes.Internal, "接收数据失败: %v", err)
	}

	agentID := firstData.AgentId
	if agentID == "" {
		return status.Errorf(codes.InvalidArgument, "Agent ID 不能为空")
	}

	// 身份校验：把 TLS 客户端证书 CN 与上报 AgentID 绑定，杜绝伪造 AgentID 顶替他机。
	// EnforceAgentID=false 为观察模式（只告警不拒绝，供存量迁移），=true 为强制模式（步骤 6）。
	leafCert, hasClientCert := peerLeafCert(stream.Context())
	if hasClientCert && s.isRevokedSerial(leafCert.SerialNumber) {
		s.logger.Warn("拒绝已吊销证书的连接",
			zap.String("agent_id", agentID),
			zap.String("serial", leafCert.SerialNumber.String()),
		)
		return status.Errorf(codes.PermissionDenied, "客户端证书已吊销")
	}
	if s.cfg.MTLS.EnforceAgentID {
		if hasClientCert {
			if leafCert.Subject.CommonName != agentID {
				s.logger.Warn("强制模式：拒绝 CN 与 AgentID 不符的连接",
					zap.String("cert_cn", leafCert.Subject.CommonName),
					zap.String("agent_id", agentID),
				)
				return status.Errorf(codes.PermissionDenied, "客户端证书 CN 与上报 AgentID 不符")
			}
		} else if !s.enrollTokenValid(enrollTokenFromCtx(stream.Context())) {
			s.logger.Warn("强制模式：拒绝无有效客户端证书且 enroll 令牌无效的连接",
				zap.String("agent_id", agentID),
			)
			return status.Errorf(codes.Unauthenticated, "缺少有效客户端证书，且 enroll 令牌无效")
		}
	} else if hasClientCert && leafCert.Subject.CommonName != agentID {
		// 观察模式降 Debug：迁移期 500 台重连会高频命中，Warn 会刷屏。
		// 真正该拦截的场景由强制模式（EnforceAgentID=true）的 Warn + 拒绝兜底。
		s.logger.Debug("观察模式：客户端证书 CN 与上报 AgentID 不符（迁移期允许，强制后将拒绝）",
			zap.String("cert_cn", leafCert.Subject.CommonName),
			zap.String("agent_id", agentID),
		)
	}

	s.logger.Info("Agent 连接",
		zap.String("agent_id", agentID),
		zap.String("hostname", firstData.Hostname),
		zap.String("version", firstData.Version),
		zap.Strings("ipv4", append(firstData.IntranetIpv4, firstData.ExtranetIpv4...)),
		zap.Strings("ipv6", append(firstData.IntranetIpv6, firstData.ExtranetIpv6...)),
	)

	// 创建连接对象
	conn := &Connection{
		AgentID:  agentID,
		Hostname: firstData.Hostname,
		IPv4:     append(firstData.IntranetIpv4, firstData.ExtranetIpv4...),
		IPv6:     append(firstData.IntranetIpv6, firstData.ExtranetIpv6...),
		Version:  firstData.Version,
		LastSeen: time.Now(),
		stream:   stream,
		ctx:      ctx,
		cancel:   cancel,
		// sendCh 容量 100: precheck cron 单 host 单 tick 可投 200 条 task,
		// 加上 plugin update/rule sync/heartbeat ack 共用此 ch,
		// 容量过小(原 10)会导致 agent stream 短暂卡住时 SendCommand 立即 drop,
		// 影响 update push 等关键命令投递。
		sendCh:    make(chan *grpcProto.Command, 100),
		workerSem: make(chan struct{}, 10),
	}

	// 注册连接
	s.registerConnection(agentID, conn)
	defer s.unregisterConnection(agentID, conn)

	// 检查并发送 Agent 上线恢复通知（如果之前离线）
	go s.checkAndSendAgentOnlineNotification(agentID, conn)

	// 检查并下发证书（首次连接时）。已持有匹配 CN 单机证书的连接无需重复下发。
	alreadyEnrolled := hasClientCert && leafCert.Subject.CommonName == agentID
	if err := s.sendCertificateBundleIfNeeded(ctx, conn, hasClientCert, alreadyEnrolled); err != nil {
		s.logger.Error("下发证书包失败", zap.Error(err), zap.String("agent_id", agentID))
		// 证书下发失败不影响连接，继续处理
	}

	// 下发插件配置（首次连接时）
	runtimeType := s.getAgentRuntimeType(agentID)
	if err := s.sendPluginConfigsIfNeeded(ctx, conn, runtimeType); err != nil {
		s.logger.Error("下发插件配置失败", zap.Error(err), zap.String("agent_id", agentID))
		// 插件配置下发失败不影响连接，继续处理
	}

	// 处理第一个数据包（心跳）
	if err := s.handlePackagedData(ctx, firstData, conn); err != nil {
		s.logger.Error("处理数据包失败", zap.Error(err), zap.String("agent_id", agentID))
	}

	// 启动发送 goroutine
	go s.sendLoop(conn)

	// 接收循环
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			data, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					s.logger.Info("Agent 断开连接（EOF）",
						zap.String("agent_id", agentID),
						zap.String("hostname", conn.Hostname),
					)
					return nil
				}
				// context canceled / transport closing 是 Agent 重连的正常现象，降为 Debug
				if ctx.Err() != nil || status.Code(err) == codes.Canceled || status.Code(err) == codes.Unavailable {
					s.logger.Debug("Agent 连接已关闭",
						zap.String("agent_id", agentID),
						zap.String("reason", err.Error()),
					)
					return nil
				}
				s.logger.Error("接收数据失败",
					zap.Error(err),
					zap.String("agent_id", agentID),
					zap.String("error_type", fmt.Sprintf("%T", err)),
				)
				return status.Errorf(codes.Internal, "接收数据失败: %v", err)
			}

			s.logger.Debug("收到Agent数据",
				zap.String("agent_id", agentID),
				zap.String("hostname", data.Hostname),
				zap.String("version", data.Version),
				zap.String("product", data.Product),
				zap.Int("record_count", len(data.Records)),
			)

			// 更新连接信息（仅更新非空字段，避免插件数据覆盖心跳数据）
			conn.mu.Lock()
			conn.LastSeen = time.Now()
			if data.Hostname != "" {
				conn.Hostname = data.Hostname
			}
			if len(data.IntranetIpv4) > 0 || len(data.ExtranetIpv4) > 0 {
				conn.IPv4 = append(data.IntranetIpv4, data.ExtranetIpv4...)
			}
			if len(data.IntranetIpv6) > 0 || len(data.ExtranetIpv6) > 0 {
				conn.IPv6 = append(data.IntranetIpv6, data.ExtranetIpv6...)
			}
			conn.mu.Unlock()

			// 处理数据包
			if err := s.handlePackagedData(ctx, data, conn); err != nil {
				s.logger.Error("处理数据包失败", zap.Error(err), zap.String("agent_id", agentID))
				// 继续处理下一个数据包，不中断连接
			}
		}
	}
}

// handlePackagedData 处理 PackagedData
func (s *Service) handlePackagedData(ctx context.Context, data *grpcProto.PackagedData, conn *Connection) error {
	// 处理心跳数据（从 PackagedData 中提取）
	if err := s.handleHeartbeat(ctx, data, conn); err != nil {
		s.logger.Error("处理心跳失败", zap.Error(err), zap.String("agent_id", conn.AgentID))
	}

	// 异步处理 EncodedRecord 列表（避免重 DB 操作阻塞 Recv 循环导致 agent 超时断连）
	for _, record := range data.Records {
		select {
		case conn.workerSem <- struct{}{}:
			go func() {
				defer func() { <-conn.workerSem }()
				if err := s.handleEncodedRecord(ctx, record, conn); err != nil {
					s.logger.Error("处理记录失败",
						zap.Error(err),
						zap.String("agent_id", conn.AgentID),
						zap.Int32("data_type", record.DataType),
					)
				}
			}()
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// handleHeartbeat 处理心跳数据
func (s *Service) handleHeartbeat(ctx context.Context, data *grpcProto.PackagedData, conn *Connection) error {
	// 解析心跳记录中的额外字段
	var osInfo map[string]string
	var hardwareInfo map[string]string
	var networkInfo map[string]string
	var systemBootTime *time.Time
	var agentStartTime *time.Time
	var isContainer bool
	var containerID string
	var businessLine string
	var runtimeType model.RuntimeType = model.RuntimeTypeVM // 默认为 VM
	var podName, podNamespace, podUID string
	// EDR 引擎状态
	var edrMode, edrCapabilities, edrHookType string
	var edrEventsFwd, edrEventsDrop, edrRulesMatched, edrIOCMatched int64
	var edrRulesVersion, edrIOCVersion string
	var edrRulesCount, edrIOCCount int
	var hasHeartbeatData bool // 是否包含心跳数据
	if len(data.Records) > 0 {
		for _, record := range data.Records {
			if record.DataType == 1000 { // 心跳数据类型
				hasHeartbeatData = true
				// 解析 bridge.Record 获取OS、硬件和网络信息
				var bridgeRecord bridge.Record
				if err := proto.Unmarshal(record.Data, &bridgeRecord); err == nil {
					if bridgeRecord.Data != nil && bridgeRecord.Data.Fields != nil {
						fields := bridgeRecord.Data.Fields
						// OS信息（含 P5.3 livepatch 能力）
						osInfo = map[string]string{
							"os_family":          fields["os_family"],
							"os_version":         fields["os_version"],
							"kernel_version":     fields["kernel"],
							"arch":               fields["arch"],
							"livepatch_enabled":  fields["livepatch_enabled"],
							"livepatch_provider": fields["livepatch_provider"],
							"active_livepatches": fields["active_livepatches"],
						}
						// 硬件信息
						hardwareInfo = map[string]string{
							"device_model":  fields["device_model"],
							"manufacturer":  fields["manufacturer"],
							"device_serial": fields["device_serial"],
							"cpu_info":      fields["cpu_info"],
							"memory_size":   fields["memory_size"],
							"system_load":   fields["system_load"],
						}
						// 网络信息
						networkInfo = map[string]string{
							"default_gateway": fields["default_gateway"],
							"dns_servers":     fields["dns_servers"],
							"network_mode":    fields["network_mode"],
						}
						// 磁盘和网卡信息（JSON 格式）
						if diskInfoStr, ok := fields["disk_info"]; ok && diskInfoStr != "" {
							networkInfo["disk_info"] = diskInfoStr
							s.logger.Debug("收到磁盘信息",
								zap.String("agent_id", conn.AgentID),
								zap.String("disk_info_length", fmt.Sprintf("%d", len(diskInfoStr))))
						} else {
							s.logger.Debug("未收到磁盘信息",
								zap.String("agent_id", conn.AgentID),
								zap.Bool("field_exists", ok))
						}
						if networkInterfacesStr, ok := fields["network_interfaces"]; ok && networkInterfacesStr != "" {
							networkInfo["network_interfaces"] = networkInterfacesStr
							s.logger.Debug("收到网卡信息",
								zap.String("agent_id", conn.AgentID),
								zap.String("network_interfaces_length", fmt.Sprintf("%d", len(networkInterfacesStr))))
						} else {
							s.logger.Debug("未收到网卡信息",
								zap.String("agent_id", conn.AgentID),
								zap.Bool("field_exists", ok))
						}
						// 解析系统启动时间
						if bootTimeStr, ok := fields["system_boot_time"]; ok && bootTimeStr != "" {
							if bootTime, err := time.Parse(time.RFC3339, bootTimeStr); err == nil {
								systemBootTime = &bootTime
							}
						}
						// 解析客户端启动时间
						if startTimeStr, ok := fields["agent_start_time"]; ok && startTimeStr != "" {
							if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
								agentStartTime = &startTime
							}
						}
						// 解析运行时类型
						if rtStr, ok := fields["runtime_type"]; ok && rtStr != "" {
							switch rtStr {
							case "vm":
								runtimeType = model.RuntimeTypeVM
							case "docker":
								runtimeType = model.RuntimeTypeDocker
							case "k8s":
								runtimeType = model.RuntimeTypeK8s
							default:
								runtimeType = model.RuntimeTypeVM
							}
						}
						// 解析容器环境标识
						if isContainerStr, ok := fields["is_container"]; ok && isContainerStr == "true" {
							isContainer = true
							if cid, ok := fields["container_id"]; ok && cid != "" {
								containerID = cid
							}
							// 如果是容器但 runtime_type 仍为默认值 VM，则修正为 Docker
							if runtimeType == model.RuntimeTypeVM {
								runtimeType = model.RuntimeTypeDocker
								s.logger.Debug("修正容器运行时类型",
									zap.String("agent_id", conn.AgentID),
									zap.String("runtime_type", string(runtimeType)))
							}
						}
						// 解析 K8s 相关字段
						if pn, ok := fields["pod_name"]; ok && pn != "" {
							podName = pn
						}
						if pns, ok := fields["pod_namespace"]; ok && pns != "" {
							podNamespace = pns
						}
						if puid, ok := fields["pod_uid"]; ok && puid != "" {
							podUID = puid
						}
						// 解析业务线（如果 Agent 提供了）
						if bl, ok := fields["business_line"]; ok && bl != "" {
							businessLine = bl
							s.logger.Debug("收到业务线信息",
								zap.String("agent_id", conn.AgentID),
								zap.String("business_line", businessLine))
						}
						// 解析 EDR 引擎状态
						if v, ok := fields["edr_mode"]; ok && v != "" {
							edrMode = v
							edrCapabilities = fields["edr_capabilities"]
							edrHookType = fields["edr_hook_type"]
							edrRulesVersion = fields["edr_rules_version"]
							edrIOCVersion = fields["edr_ioc_version"]
							if n, err := strconv.ParseInt(fields["edr_events_fwd"], 10, 64); err == nil {
								edrEventsFwd = n
							}
							if n, err := strconv.ParseInt(fields["edr_events_drop"], 10, 64); err == nil {
								edrEventsDrop = n
							}
							if n, err := strconv.Atoi(fields["edr_rules_count"]); err == nil {
								edrRulesCount = n
							}
							if n, err := strconv.ParseInt(fields["edr_rules_matched"], 10, 64); err == nil {
								edrRulesMatched = n
							}
							if n, err := strconv.Atoi(fields["edr_ioc_count"]); err == nil {
								edrIOCCount = n
							}
							if n, err := strconv.ParseInt(fields["edr_ioc_matched"], 10, 64); err == nil {
								edrIOCMatched = n
							}
						}
						// 解析并存储插件状态
						if pluginStatsStr, ok := fields["plugin_stats"]; ok && pluginStatsStr != "" {
							if err := s.storeHostPlugins(ctx, conn.AgentID, pluginStatsStr); err != nil {
								s.logger.Warn("存储插件状态失败",
									zap.String("agent_id", conn.AgentID),
									zap.Error(err))
							}
						}
					}
				}
				// 存储资源监控数据
				if err := s.storeHostMetrics(ctx, conn.AgentID, record); err != nil {
					s.logger.Warn("failed to store host metrics", zap.String("agent_id", conn.AgentID), zap.Error(err))
					// 不返回错误，避免影响心跳处理
				}
			}
		}
	}

	// 解析DNS服务器列表
	var dnsServers model.StringArray
	if dnsServersStr, ok := networkInfo["dns_servers"]; ok && dnsServersStr != "" {
		servers := strings.Split(dnsServersStr, ",")
		// 去除空格
		for i, s := range servers {
			servers[i] = strings.TrimSpace(s)
		}
		dnsServers = model.StringArray(servers)
	}

	// 版本诊断和备选方案
	agentVersion := data.Version
	versionSource := "PackagedData.Version"

	// 如果 PackagedData.Version 为空，尝试从心跳记录中提取（备选方案）
	if agentVersion == "" && hasHeartbeatData {
		// 从心跳记录的 fields 中提取版本（Agent 在 heartbeat.go:106 中也会放入 version 字段）
		for _, record := range data.Records {
			if record.DataType == 1000 {
				var bridgeRecord bridge.Record
				if err := proto.Unmarshal(record.Data, &bridgeRecord); err == nil {
					if bridgeRecord.Data != nil && bridgeRecord.Data.Fields != nil {
						if v, ok := bridgeRecord.Data.Fields["version"]; ok && v != "" {
							agentVersion = v
							versionSource = "heartbeat.fields.version"
							s.logger.Info("从心跳记录中提取版本",
								zap.String("agent_id", conn.AgentID),
								zap.String("version", agentVersion),
								zap.String("source", versionSource),
							)
							break
						}
					}
				}
			}
		}
	}

	// 版本诊断日志（仅在心跳数据时输出，插件数据不含版本信息）
	if hasHeartbeatData {
		if agentVersion == "" {
			s.logger.Warn("Agent 版本为空",
				zap.String("agent_id", conn.AgentID),
				zap.String("hostname", data.Hostname),
				zap.String("product", data.Product),
				zap.String("hint", "请检查 Agent 构建时是否正确嵌入了版本信息（-ldflags \"-X main.buildVersion=VERSION\"）"),
			)
		} else {
			s.logger.Debug("Agent 版本信息",
				zap.String("agent_id", conn.AgentID),
				zap.String("hostname", data.Hostname),
				zap.String("version", agentVersion),
				zap.String("source", versionSource),
				zap.String("product", data.Product),
			)
		}
	}

	// 非心跳数据（如插件数据）不需要更新主机记录，提前返回
	if !hasHeartbeatData && data.Hostname == "" {
		return nil
	}

	// 更新或创建主机记录
	nowLocal := model.ToLocalTime(time.Now())
	host := &model.Host{
		HostID:        conn.AgentID,
		Hostname:      data.Hostname,
		IPv4:          model.StringArray(append(data.IntranetIpv4, data.ExtranetIpv4...)),
		IPv6:          model.StringArray(append(data.IntranetIpv6, data.ExtranetIpv6...)),
		Status:        model.HostStatusOnline,
		LastHeartbeat: &nowLocal,
		AgentVersion:  agentVersion, // Agent 版本号（可能来自 PackagedData 或心跳记录）
		// OS信息
		OSFamily:      osInfo["os_family"],
		OSVersion:     osInfo["os_version"],
		KernelVersion: osInfo["kernel_version"],
		Arch:          osInfo["arch"],
		// P5.3 kernel livepatch
		KernelLivepatchEnabled:  osInfo["livepatch_enabled"] == "true",
		KernelLivepatchProvider: osInfo["livepatch_provider"],
		ActiveLivepatches:       osInfo["active_livepatches"],
		// 硬件信息
		DeviceModel:  hardwareInfo["device_model"],
		Manufacturer: hardwareInfo["manufacturer"],
		DeviceSerial: hardwareInfo["device_serial"],
		CPUInfo:      hardwareInfo["cpu_info"],
		MemorySize:   hardwareInfo["memory_size"],
		SystemLoad:   hardwareInfo["system_load"],
		// 网络信息
		DefaultGateway: networkInfo["default_gateway"],
		DNSServers:     dnsServers,
		NetworkMode:    networkInfo["network_mode"],
		// 磁盘和网卡信息
		DiskInfo:          networkInfo["disk_info"],
		NetworkInterfaces: networkInfo["network_interfaces"],
		// 运行时环境
		RuntimeType: runtimeType,
		IsContainer: isContainer,
		ContainerID: containerID,
		// K8s 相关字段
		PodName:      podName,
		PodNamespace: podNamespace,
		PodUID:       podUID,
		// 时间信息
		SystemBootTime: model.ToLocalTimePtr(systemBootTime),
		AgentStartTime: model.ToLocalTimePtr(agentStartTime),
		// 业务线（如果 Agent 提供了，则使用；否则保持现有值）
		BusinessLine: businessLine,
		// EDR 引擎状态
		EDRMode:            edrMode,
		EDRCapabilities:    edrCapabilities,
		EDRHookType:        edrHookType,
		EDREventsForwarded: edrEventsFwd,
		EDREventsDropped:   edrEventsDrop,
		EDRRulesVersion:    edrRulesVersion,
		EDRRulesCount:      edrRulesCount,
		EDRRulesMatched:    edrRulesMatched,
		EDRIOCVersion:      edrIOCVersion,
		EDRIOCCount:        edrIOCCount,
		EDRIOCMatched:      edrIOCMatched,
	}

	// 使用 Save 方法（如果不存在则创建，存在则更新）
	result := s.db.Where("host_id = ?", conn.AgentID).FirstOrCreate(host)
	if result.Error != nil {
		return fmt.Errorf("查询主机失败: %w", result.Error)
	}

	// 如果主机已存在，更新字段
	if result.RowsAffected == 0 {
		updates := map[string]interface{}{
			"hostname":       data.Hostname,
			"ipv4":           model.StringArray(append(data.IntranetIpv4, data.ExtranetIpv4...)),
			"ipv6":           model.StringArray(append(data.IntranetIpv6, data.ExtranetIpv6...)),
			"status":         model.HostStatusOnline,
			"last_heartbeat": time.Now(),
			"agent_version":  agentVersion, // Agent 版本号（可能来自 PackagedData 或心跳记录）
		}
		// 只有当数据包中包含心跳数据时才更新这些字段
		if hasHeartbeatData {
			updates["os_family"] = osInfo["os_family"]
			updates["os_version"] = osInfo["os_version"]
			updates["kernel_version"] = osInfo["kernel_version"]
			updates["arch"] = osInfo["arch"]
			// P5.3 kernel livepatch
			updates["kernel_livepatch_enabled"] = osInfo["livepatch_enabled"] == "true"
			updates["kernel_livepatch_provider"] = osInfo["livepatch_provider"]
			updates["active_livepatches"] = osInfo["active_livepatches"]
			updates["device_model"] = hardwareInfo["device_model"]
			updates["manufacturer"] = hardwareInfo["manufacturer"]
			updates["device_serial"] = hardwareInfo["device_serial"]
			updates["cpu_info"] = hardwareInfo["cpu_info"]
			updates["memory_size"] = hardwareInfo["memory_size"]
			updates["system_load"] = hardwareInfo["system_load"]
			updates["default_gateway"] = networkInfo["default_gateway"]
			updates["dns_servers"] = dnsServers
			updates["network_mode"] = networkInfo["network_mode"]
			updates["disk_info"] = networkInfo["disk_info"]
			updates["network_interfaces"] = networkInfo["network_interfaces"]
			updates["runtime_type"] = runtimeType
			updates["is_container"] = isContainer
			updates["container_id"] = containerID
			updates["pod_name"] = podName
			updates["pod_namespace"] = podNamespace
			updates["pod_uid"] = podUID
			updates["system_boot_time"] = systemBootTime
			updates["agent_start_time"] = agentStartTime
			// EDR 引擎状态
			if edrMode != "" {
				updates["edr_mode"] = edrMode
				updates["edr_capabilities"] = edrCapabilities
				updates["edr_hook_type"] = edrHookType
				updates["edr_events_fwd"] = edrEventsFwd
				updates["edr_events_drop"] = edrEventsDrop
				updates["edr_rules_version"] = edrRulesVersion
				updates["edr_rules_count"] = edrRulesCount
				updates["edr_rules_matched"] = edrRulesMatched
				updates["edr_ioc_version"] = edrIOCVersion
				updates["edr_ioc_count"] = edrIOCCount
				updates["edr_ioc_matched"] = edrIOCMatched
			}
		}
		// 如果 Agent 提供了业务线，则更新（仅在首次设置或 Agent 明确提供时更新）
		if businessLine != "" {
			updates["business_line"] = businessLine
		}
		// 只更新非空字段（但 agent_version 只有在非空时才更新）
		cleanUpdates := make(map[string]interface{})
		for k, v := range updates {
			if v == nil {
				continue
			}
			// agent_version 字段只有在非空时才更新（避免覆盖已有版本为空）
			if k == "agent_version" {
				if str, ok := v.(string); ok && str != "" {
					cleanUpdates[k] = v
				}
				continue
			}
			// 对于字符串，检查是否为空
			if str, ok := v.(string); ok {
				if str == "" {
					continue
				}
			}
			// 对于字符串数组，检查是否为空
			if strArray, ok := v.(model.StringArray); ok {
				if len(strArray) > 0 {
					cleanUpdates[k] = v
				}
			} else {
				// 对于时间指针，只有非 nil 时才更新
				if _, ok := v.(*time.Time); ok {
					cleanUpdates[k] = v
				} else {
					cleanUpdates[k] = v
				}
			}
		}
		if err := s.db.Model(&model.Host{}).Where("host_id = ?", conn.AgentID).Updates(cleanUpdates).Error; err != nil {
			return fmt.Errorf("更新主机失败: %w", err)
		}
	}

	s.logger.Debug("心跳处理完成",
		zap.String("agent_id", conn.AgentID),
		zap.String("hostname", data.Hostname),
		zap.String("agent_version", agentVersion),
		zap.String("version_source", versionSource),
		zap.Bool("has_disk_info", networkInfo["disk_info"] != ""),
		zap.Bool("has_network_interfaces", networkInfo["network_interfaces"] != ""),
	)

	return nil
}

// storeHostPlugins 存储主机插件状态
func (s *Service) storeHostPlugins(ctx context.Context, hostID string, pluginStatsJSON string) error {
	// 解析插件状态 JSON
	// 格式: {"baseline": {"status": "running", "version": "1.0.3", "start_time": 1234567890}, ...}
	var pluginStats map[string]struct {
		Status    string `json:"status"`
		Version   string `json:"version"`
		StartTime int64  `json:"start_time"`
	}

	if err := json.Unmarshal([]byte(pluginStatsJSON), &pluginStats); err != nil {
		return fmt.Errorf("解析插件状态 JSON 失败: %w", err)
	}

	if len(pluginStats) == 0 {
		return nil
	}

	s.logger.Debug("收到插件状态",
		zap.String("host_id", hostID),
		zap.Int("plugin_count", len(pluginStats)))

	// 批量查询该主机的所有现有插件记录（消除 N+1）
	var existingPlugins []model.HostPlugin
	if err := s.db.Where("host_id = ? AND deleted_at IS NULL", hostID).Find(&existingPlugins).Error; err != nil {
		return fmt.Errorf("批量查询插件状态失败: %w", err)
	}
	existingMap := make(map[string]*model.HostPlugin, len(existingPlugins))
	for i := range existingPlugins {
		existingMap[existingPlugins[i].Name] = &existingPlugins[i]
	}

	// 更新或创建每个插件的状态
	for name, stats := range pluginStats {
		// 转换状态
		var status model.HostPluginStatus
		switch stats.Status {
		case "running":
			status = model.HostPluginStatusRunning
		case "stopped":
			status = model.HostPluginStatusStopped
		case "error":
			status = model.HostPluginStatusError
		case "dormant":
			status = model.HostPluginStatusDormant
		default:
			status = model.HostPluginStatusRunning
		}

		// 转换启动时间
		var startTime *model.LocalTime
		if stats.StartTime > 0 {
			t := model.ToLocalTime(time.Unix(stats.StartTime, 0))
			startTime = &t
		}

		if existing, ok := existingMap[name]; ok {
			// 记录存在，更新
			updates := map[string]any{
				"version":    stats.Version,
				"status":     status,
				"start_time": startTime,
			}
			if err := s.db.Model(existing).Updates(updates).Error; err != nil {
				s.logger.Error("更新插件状态失败",
					zap.String("host_id", hostID),
					zap.String("plugin_name", name),
					zap.Error(err))
				continue
			}
		} else {
			// 记录不存在，创建新记录
			hostPlugin := model.HostPlugin{
				HostID:    hostID,
				Name:      name,
				Version:   stats.Version,
				Status:    status,
				StartTime: startTime,
			}
			if err := s.db.Create(&hostPlugin).Error; err != nil {
				s.logger.Error("创建插件状态失败",
					zap.String("host_id", hostID),
					zap.String("plugin_name", name),
					zap.Error(err))
				continue
			}
		}

		s.logger.Debug("更新插件状态成功",
			zap.String("host_id", hostID),
			zap.String("plugin_name", name),
			zap.String("version", stats.Version),
			zap.String("status", string(status)))
	}

	return nil
}

// storeHostMetrics 存储主机监控指标
// 优先写入 Prometheus in-process Gauge（由 Prometheus Server 抓取），
// 不可用时降级写 MySQL。
func (s *Service) storeHostMetrics(_ context.Context, hostID string, record *grpcProto.EncodedRecord) error {
	var bridgeRecord bridge.Record
	if err := proto.Unmarshal(record.Data, &bridgeRecord); err != nil {
		return fmt.Errorf("failed to unmarshal bridge record: %w", err)
	}
	if bridgeRecord.Data == nil || bridgeRecord.Data.Fields == nil {
		return nil
	}
	fields := bridgeRecord.Data.Fields

	metric := &model.HostMetric{
		HostID:      hostID,
		CollectedAt: model.ToLocalTime(time.Unix(0, record.Timestamp)),
	}
	gaugeMap := make(map[string]float64)

	if v := parseFloat(fields["cpu_usage"]); v != nil {
		metric.CPUUsage = v
		gaugeMap["cpu_usage"] = *v
	}
	if v := parseFloat(fields["mem_usage"]); v != nil {
		metric.MemUsage = v
		gaugeMap["mem_usage"] = *v
	}
	if v := parseFloat(fields["disk_usage"]); v != nil {
		metric.DiskUsage = v
		gaugeMap["disk_usage"] = *v
	}
	if v := parseFloat(fields["net_in"]); v != nil {
		u := uint64(*v)
		metric.NetBytesRecv = &u
		gaugeMap["net_in"] = *v
	}
	if v := parseFloat(fields["net_out"]); v != nil {
		u := uint64(*v)
		metric.NetBytesSent = &u
		gaugeMap["net_out"] = *v
	}
	if v := parseFloat(fields["disk_read_bytes"]); v != nil {
		gaugeMap["disk_read_bytes"] = *v
	}
	if v := parseFloat(fields["disk_write_bytes"]); v != nil {
		gaugeMap["disk_write_bytes"] = *v
	}
	if v := parseFloat(fields["agent_cpu_usage"]); v != nil {
		gaugeMap["agent_cpu_usage"] = *v
	}
	if v := parseFloat(fields["agent_mem_rss"]); v != nil {
		gaugeMap["agent_mem_rss"] = *v
	}
	if v := parseFloat(fields["agent_mem_percent"]); v != nil {
		gaugeMap["agent_mem_percent"] = *v
	}

	if len(gaugeMap) == 0 {
		return nil
	}

	// 取 hostname（尽量携带，label 更易读）
	hostname := fields["hostname"]

	// 更新 Prometheus Gauge（in-process，Prometheus Server 抓取 /metrics）
	metrics.Update(hostID, hostname, gaugeMap)

	// 同时写 MySQL（供无 Prometheus 环境降级使用）
	if s.metricsBuffer != nil {
		if err := s.metricsBuffer.Add(metric); err != nil {
			s.logger.Warn("监控数据写 MySQL 失败",
				zap.String("host_id", hostID),
				zap.Error(err),
			)
		}
	}

	return nil
}

// parseFloat 解析浮点数
func parseFloat(s string) *float64 {
	var f float64
	if _, err := fmt.Sscanf(s, "%f", &f); err != nil {
		return nil
	}
	return &f
}

// handleEncodedRecord 处理 EncodedRecord
// 若 Kafka 生产者已注入，则将记录发布到对应 Topic（异步解耦，μs 级返回）；
// 否则回退到直接写 MySQL（向后兼容）。
func (s *Service) handleEncodedRecord(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	// ---- AC 直处理：部分 DataType 不走 Kafka，在 AC 侧直接处理 ----
	// 6004: FIM 基线快照 — 涉及 GORM 事务和基线表 upsert，不适合走 Kafka → Consumer
	if record.DataType == 6004 {
		return s.handleFIMBaselineSnapshot(ctx, record, conn)
	}

	// ---- Kafka 路径 ----
	if s.kafkaProducer != nil {
		msg := &kafka.MQMessage{
			DataType:     record.DataType,
			AgentID:      conn.AgentID,
			Body:         record.Data,
			AgentTime:    record.Timestamp / int64(time.Second), // Timestamp 是纳秒，转成 Unix 秒
			SvrTime:      time.Now().Unix(),
			Hostname:     conn.GetHostname(),
			IntranetIPv4: strings.Join(conn.GetIPv4(), ","),
			Version:      conn.GetVersion(),
			ACID:         s.cfg.Server.InstanceID,
		}
		topic := kafka.RouteDataType(record.DataType, s.cfg.Kafka.TopicPrefix)
		if err := s.kafkaProducer.Send(topic, conn.AgentID, msg); err != nil {
			s.logger.Warn("Kafka 发送失败，消息已入降级队列或丢弃",
				zap.String("agent_id", conn.AgentID),
				zap.Int32("data_type", record.DataType),
				zap.Error(err),
			)
		}
		return nil
	}

	// ---- MySQL 直写路径（向后兼容，Kafka 未启用时） ----
	switch record.DataType {
	case 1000: // Agent 心跳（已在 handleHeartbeat 中处理）
		return nil

	case 8000: // 基线检查结果
		return s.handleBaselineResult(ctx, record, conn)

	case 8001: // 任务完成信号
		return s.handleTaskCompletion(ctx, record, conn)

	case 8003: // 基线修复结果
		return s.handleFixResult(ctx, record, conn)

	case 8004: // 修复任务完成信号
		return s.handleFixTaskComplete(ctx, record, conn)

	case 6001: // FIM 事件
		return s.handleFIMEvent(ctx, record, conn)

	case 6002: // FIM 任务完成信号
		return s.handleFIMTaskCompletion(ctx, record, conn)

	case 6004: // FIM 基线快照（首次扫描上报）
		return s.handleFIMBaselineSnapshot(ctx, record, conn)

	case 5050, 5051, 5052, 5053, 5054, 5055, 5056, 5057, 5058, 5059, 5060:
		// 资产数据
		return s.assetService.HandleAssetData(conn.AgentID, record.DataType, record.Data)

	case 7001: // Scanner 扫描结果
		return s.handleScanResult(ctx, record, conn)

	case 7002: // Scanner 任务完成
		return s.handleScanTaskComplete(ctx, record, conn)

	case 7004: // Scanner 隔离/删除结果
		return s.handleQuarantineResult(ctx, record, conn)

	case 9200: // 漏洞修复任务结果（与 plugins/remediation 的 dataTypeRemediationResult 对齐）
		return s.handleRemediationResult(ctx, record, conn)

	default:
		s.logger.Debug("未知数据类型",
			zap.String("agent_id", conn.AgentID),
			zap.Int32("data_type", record.DataType),
		)
		return nil
	}
}

// handleBaselineResult 处理基线检查结果
func (s *Service) handleBaselineResult(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	// 解析 EncodedRecord.data 为 bridge.Record
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析 Record 失败: %w", err)
	}

	// 从 Payload 中提取字段
	if bridgeRecord.Data == nil {
		return fmt.Errorf("Record.Data 为空")
	}
	fields := bridgeRecord.Data.Fields

	// 提取必要字段（复合主键 task_id + host_id + rule_id 天然保证唯一，不再需要 result_id）
	hostID := conn.AgentID
	policyID := fields["policy_id"]
	ruleID := fields["rule_id"]
	taskID := fields["task_id"]
	status := fields["status"]
	severity := fields["severity"]
	category := fields["category"]
	title := fields["title"]
	actual := fields["actual"]
	expected := fields["expected"]
	fixSuggestion := fields["fix_suggestion"]

	// 解析时间戳
	timestamp := time.Unix(0, record.Timestamp)
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// 转换为 ResultStatus
	var resultStatus model.ResultStatus
	switch status {
	case "pass":
		resultStatus = model.ResultStatusPass
	case "fail":
		resultStatus = model.ResultStatusFail
	case "error":
		resultStatus = model.ResultStatusError
	case "na":
		resultStatus = model.ResultStatusNA
	default:
		resultStatus = model.ResultStatusError
	}

	// 获取策略名称（用于冗余存储，避免策略删除后数据丢失）
	var policyName string
	if policyID != "" {
		var policy model.Policy
		if err := s.db.Select("name").Where("id = ?", policyID).First(&policy).Error; err == nil {
			policyName = policy.Name
		}
	}

	// 创建 ScanResult（复合主键 task_id + host_id + rule_id）
	scanResult := &model.ScanResult{
		TaskID:        taskID,
		HostID:        hostID,
		RuleID:        ruleID,
		Hostname:      conn.GetHostname(),
		PolicyID:      policyID,
		PolicyName:    policyName,
		Status:        resultStatus,
		Severity:      severity,
		Category:      category,
		Title:         title,
		Actual:        actual,
		Expected:      expected,
		FixSuggestion: fixSuggestion,
		CheckedAt:     model.ToLocalTime(timestamp),
	}

	// 保存到数据库（复合主键 task_id + host_id + rule_id 保证幂等）
	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "task_id"}, {Name: "host_id"}, {Name: "rule_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "actual", "expected", "checked_at", "severity", "fix_suggestion", "hostname", "policy_name"}),
	}).Create(scanResult).Error; err != nil {
		return fmt.Errorf("保存检测结果失败: %w", err)
	}

	s.logger.Debug("检测结果已保存",
		zap.String("agent_id", conn.AgentID),
		zap.String("task_id", taskID),
		zap.String("rule_id", ruleID),
		zap.String("status", string(resultStatus)),
	)

	// 如果检测结果为 fail，创建或更新告警
	if resultStatus == model.ResultStatusFail {
		if err := s.createOrUpdateAlert(scanResult, conn); err != nil {
			s.logger.Warn("创建或更新告警失败",
				zap.String("host_id", hostID),
				zap.String("rule_id", ruleID),
				zap.Error(err),
			)
		}
	} else if resultStatus == model.ResultStatusPass {
		// 如果检测结果为 pass，检查是否有活跃告警需要恢复
		if err := s.resolveAlertIfExists(scanResult, conn); err != nil {
			s.logger.Warn("解决告警失败",
				zap.String("host_id", hostID),
				zap.String("rule_id", ruleID),
				zap.Error(err),
			)
		}
	}

	return nil
}

// scanResultAlertKey 生成基线扫描告警的去重键（同一主机同一规则只需一个告警）
func scanResultAlertKey(hostID, ruleID string) string {
	return "baseline-" + hostID + "-" + ruleID
}

// createOrUpdateAlert 创建或更新告警
func (s *Service) createOrUpdateAlert(scanResult *model.ScanResult, conn *Connection) error {
	alertKey := scanResultAlertKey(scanResult.HostID, scanResult.RuleID)

	// 查询是否已存在告警
	var existingAlert model.Alert
	err := s.db.Where("result_id = ?", alertKey).First(&existingAlert).Error

	now := model.Now()

	if err == gorm.ErrRecordNotFound {
		// 白名单检查：命中则跳过告警创建
		if s.isAlertWhitelisted(scanResult.RuleID, scanResult.HostID, scanResult.Category, scanResult.Severity) {
			s.logger.Debug("告警命中白名单，跳过创建",
				zap.String("rule_id", scanResult.RuleID),
				zap.String("host_id", scanResult.HostID),
			)
			return nil
		}

		// 创建新告警
		alert := &model.Alert{
			ResultID:      alertKey,
			HostID:        scanResult.HostID,
			RuleID:        scanResult.RuleID,
			PolicyID:      scanResult.PolicyID,
			Source:        model.AlertSourceBaseline,
			Severity:      scanResult.Severity,
			Category:      scanResult.Category,
			Title:         scanResult.Title,
			Description:   "",
			Actual:        scanResult.Actual,
			Expected:      scanResult.Expected,
			FixSuggestion: scanResult.FixSuggestion,
			Status:        model.AlertStatusActive,
			FirstSeenAt:   now,
			LastSeenAt:    now,
		}

		if err := s.db.Create(alert).Error; err != nil {
			return fmt.Errorf("创建告警失败: %w", err)
		}

		// 发送告警通知
		s.sendAlertNotification(alert, conn)

		s.logger.Debug("告警已创建",
			zap.Uint("alert_id", alert.ID),
			zap.String("host_id", scanResult.HostID),
			zap.String("rule_id", scanResult.RuleID),
		)
	} else if err == nil {
		// 更新现有告警（更新最后发现时间）
		existingAlert.LastSeenAt = now
		// 如果告警已被解决或忽略，重新激活
		if existingAlert.Status != model.AlertStatusActive {
			existingAlert.Status = model.AlertStatusActive
			existingAlert.ResolvedAt = nil
			existingAlert.ResolvedBy = ""
			existingAlert.ResolveReason = ""
		}

		if err := s.db.Save(&existingAlert).Error; err != nil {
			return fmt.Errorf("更新告警失败: %w", err)
		}

		s.logger.Debug("告警已更新",
			zap.Uint("alert_id", existingAlert.ID),
			zap.String("host_id", scanResult.HostID),
			zap.String("rule_id", scanResult.RuleID),
		)
	} else {
		return fmt.Errorf("查询告警失败: %w", err)
	}

	return nil
}

// resolveAlertIfExists 如果存在活跃告警则解决并发送恢复通知
func (s *Service) resolveAlertIfExists(scanResult *model.ScanResult, conn *Connection) error {
	alertKey := scanResultAlertKey(scanResult.HostID, scanResult.RuleID)

	// 查询是否存在活跃告警
	var existingAlert model.Alert
	err := s.db.Where("result_id = ? AND status = ?", alertKey, model.AlertStatusActive).First(&existingAlert).Error

	if err == gorm.ErrRecordNotFound {
		// 没有活跃告警，无需处理
		return nil
	}
	if err != nil {
		return fmt.Errorf("查询告警失败: %w", err)
	}

	// 解决告警
	now := model.Now()
	existingAlert.Status = model.AlertStatusResolved
	existingAlert.ResolvedAt = &now
	existingAlert.ResolvedBy = "system"
	existingAlert.ResolveReason = "检测通过，问题已修复"

	if err := s.db.Save(&existingAlert).Error; err != nil {
		return fmt.Errorf("更新告警状态失败: %w", err)
	}

	s.logger.Debug("告警已自动解决",
		zap.Uint("alert_id", existingAlert.ID),
		zap.String("host_id", scanResult.HostID),
		zap.String("rule_id", scanResult.RuleID),
	)

	// 发送告警恢复通知（异步，不阻塞）
	go func() {
		// 查询主机信息
		var host model.Host
		if err := s.db.First(&host, "host_id = ?", existingAlert.HostID).Error; err != nil {
			s.logger.Warn("查询主机信息失败", zap.String("host_id", existingAlert.HostID), zap.Error(err))
			return
		}

		// 查询规则信息
		var rule model.Rule
		if err := s.db.First(&rule, "rule_id = ?", existingAlert.RuleID).Error; err != nil {
			s.logger.Warn("查询规则信息失败", zap.String("rule_id", existingAlert.RuleID), zap.Error(err))
		}

		// 获取主机 IP
		hostIP := ""
		if len(host.IPv4) > 0 {
			hostIP = strings.Join(host.IPv4, ",")
		} else if ipv4 := conn.GetIPv4(); len(ipv4) > 0 {
			hostIP = strings.Join(ipv4, ",")
		}

		// 构建恢复数据
		resolvedData := &biz.AlertResolvedData{
			HostID:      existingAlert.HostID,
			Hostname:    host.Hostname,
			IP:          hostIP,
			OSFamily:    host.OSFamily,
			OSVersion:   host.OSVersion,
			RuleID:      existingAlert.RuleID,
			RuleName:    rule.Title,
			Category:    existingAlert.Category,
			Severity:    existingAlert.Severity,
			Title:       existingAlert.Title,
			FirstSeenAt: existingAlert.FirstSeenAt.Time(),
			ResolvedAt:  time.Now(),
			ResultID:    existingAlert.ResultID,
		}

		notificationService := biz.NewNotificationService(s.db, s.logger)
		if err := notificationService.SendAlertResolvedNotification(resolvedData); err != nil {
			s.logger.Warn("发送告警恢复通知失败",
				zap.Uint("alert_id", existingAlert.ID),
				zap.Error(err),
			)
		}
	}()

	return nil
}

// handleTaskCompletion 处理任务完成信号
func (s *Service) handleTaskCompletion(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	// 解析 EncodedRecord.data 为 bridge.Record
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析任务完成信号失败: %w", err)
	}

	// 从 Payload 中提取字段
	if bridgeRecord.Data == nil {
		return fmt.Errorf("Record.Data 为空")
	}
	fields := bridgeRecord.Data.Fields

	taskID := fields["task_id"]
	policyID := fields["policy_id"]
	status := fields["status"]
	resultCount := fields["result_count"]
	completedAt := fields["completed_at"]

	if taskID == "" {
		s.logger.Warn("任务完成信号缺少 task_id", zap.String("agent_id", conn.AgentID))
		return nil
	}

	s.logger.Info("收到任务完成信号",
		zap.String("agent_id", conn.AgentID),
		zap.String("task_id", taskID),
		zap.String("policy_id", policyID),
		zap.String("status", status),
		zap.String("result_count", resultCount),
		zap.String("completed_at", completedAt),
	)

	// 更新任务状态
	// 注意：一个任务可能分发给多个主机，我们需要跟踪每个主机的完成状态
	// 这里简化处理：当收到任何主机的完成信号时，检查是否所有主机都已完成
	// 如果全部完成，则更新任务状态为 completed

	// 查询任务
	var task model.ScanTask
	if err := s.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logger.Warn("任务不存在", zap.String("task_id", taskID))
			return nil
		}
		return fmt.Errorf("查询任务失败: %w", err)
	}

	// 如果任务已经完成或取消，不再处理
	if task.Status == model.TaskStatusCompleted || task.Status == model.TaskStatusCancelled {
		s.logger.Debug("任务已完成/取消，忽略完成信号",
			zap.String("task_id", taskID),
			zap.String("status", string(task.Status)),
		)
		return nil
	}

	// 如果任务因超时被标记为 failed，仍然允许处理完成信号
	// 因为 agent 可能实际已完成，只是完成信号到达晚于超时调度器的判定
	isRecoveryFromTimeout := task.Status == model.TaskStatusFailed

	if isRecoveryFromTimeout {
		s.logger.Info("任务已被标记为失败，但收到主机完成信号，尝试恢复",
			zap.String("task_id", taskID),
			zap.String("host_id", conn.AgentID),
			zap.String("failed_reason", task.FailedReason),
		)
	}

	// 1. 先更新 TaskHostStatus（仅从 dispatched/timeout → completed，防止重复信号时多次递增）
	now := model.Now()
	result := s.db.Model(&model.TaskHostStatus{}).
		Where("task_id = ? AND host_id = ? AND status IN ?", taskID, conn.AgentID,
			[]string{model.TaskHostStatusDispatched, model.TaskHostStatusTimeout}).
		Updates(map[string]interface{}{
			"status":        model.TaskHostStatusCompleted,
			"completed_at":  &now,
			"error_message": "",
		})

	if result.Error != nil {
		s.logger.Error("更新主机状态失败",
			zap.String("task_id", taskID),
			zap.String("host_id", conn.AgentID),
			zap.Error(result.Error),
		)
		return nil
	}

	// 没有实际更新（已经是 completed 或记录不存在），跳过后续操作
	if result.RowsAffected == 0 {
		s.logger.Debug("主机状态未变更，跳过递增（可能是重复完成信号）",
			zap.String("task_id", taskID),
			zap.String("host_id", conn.AgentID),
		)
		return nil
	}

	s.logger.Info("成功更新主机状态为已完成",
		zap.String("task_id", taskID),
		zap.String("host_id", conn.AgentID),
	)

	// 2. 状态实际发生了转移，才递增 completed_host_count
	if err := s.db.Model(&model.ScanTask{}).
		Where("task_id = ?", taskID).
		Update("completed_host_count", gorm.Expr("completed_host_count + 1")).Error; err != nil {
		s.logger.Error("递增 completed_host_count 失败", zap.String("task_id", taskID), zap.Error(err))
	}

	// 3. 重新查询任务以获取最新的完成主机数
	if err := s.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		return fmt.Errorf("查询任务失败: %w", err)
	}

	s.logger.Info("收到主机任务完成信号",
		zap.String("task_id", taskID),
		zap.String("host_id", conn.AgentID),
		zap.Int("completed_host_count", task.CompletedHostCount),
		zap.Int("dispatched_host_count", task.DispatchedHostCount),
	)

	// 4. 检查是否所有主机都已完成
	if task.DispatchedHostCount > 0 && task.CompletedHostCount >= task.DispatchedHostCount {
		// 所有主机都已返回结果，标记任务为 completed
		now := model.Now()
		updates := map[string]interface{}{
			"status":        model.TaskStatusCompleted,
			"completed_at":  &now,
			"failed_reason": "", // 清除之前超时设置的失败原因
		}

		if err := s.db.Model(&task).Updates(updates).Error; err != nil {
			return fmt.Errorf("更新任务状态失败: %w", err)
		}

		if isRecoveryFromTimeout {
			s.logger.Info("任务从超时状态恢复为已完成，所有主机都已返回结果",
				zap.String("task_id", taskID),
				zap.Int("completed_host_count", task.CompletedHostCount),
				zap.Int("dispatched_host_count", task.DispatchedHostCount),
			)
		} else {
			s.logger.Info("任务所有主机都已完成，状态更新为 completed",
				zap.String("task_id", taskID),
				zap.Int("completed_host_count", task.CompletedHostCount),
				zap.Int("dispatched_host_count", task.DispatchedHostCount),
			)
		}
	} else if isRecoveryFromTimeout {
		// 部分主机完成，更新失败原因中的数量
		remainingHosts := task.DispatchedHostCount - task.CompletedHostCount
		if remainingHosts > 0 {
			s.db.Model(&task).Update("failed_reason",
				fmt.Sprintf("任务执行超时：%d 台主机未返回结果", remainingHosts))
		}
	}

	return nil
}

// sendAlertNotification 发送告警通知（只发送立即通知模式）
func (s *Service) sendAlertNotification(alert *model.Alert, conn *Connection) {
	// 查询主机信息
	var host model.Host
	if err := s.db.First(&host, "host_id = ?", alert.HostID).Error; err != nil {
		s.logger.Warn("查询主机信息失败", zap.String("host_id", alert.HostID), zap.Error(err))
		return
	}

	// 查询规则信息
	var rule model.Rule
	if err := s.db.First(&rule, "rule_id = ?", alert.RuleID).Error; err != nil {
		s.logger.Warn("查询规则信息失败", zap.String("rule_id", alert.RuleID), zap.Error(err))
		// 规则信息不是必须的，继续发送通知
	}

	// 获取主机 IP（优先使用数据库中的 IP，如果没有则使用连接中的 IP）
	hostIP := ""
	if len(host.IPv4) > 0 {
		hostIP = strings.Join(host.IPv4, ",")
	} else if ipv4 := conn.GetIPv4(); len(ipv4) > 0 {
		hostIP = strings.Join(ipv4, ",")
	}

	// 构建告警数据
	alertData := &biz.AlertData{
		HostID:        alert.HostID,
		Hostname:      host.Hostname,
		IP:            hostIP,
		OSFamily:      host.OSFamily,
		OSVersion:     host.OSVersion,
		BusinessLine:  host.BusinessLine, // 添加业务线
		RuleID:        alert.RuleID,
		RuleName:      rule.Title,
		Category:      alert.Category,
		Severity:      alert.Severity,
		Title:         alert.Title,
		Description:   rule.Description,
		Actual:        alert.Actual,
		Expected:      alert.Expected,
		FixSuggestion: alert.FixSuggestion,
		TaskID:        "", // 可以从 ScanResult 中获取
		PolicyID:      alert.PolicyID,
		CheckedAt:     alert.LastSeenAt.Time(),
		ResultID:      alert.ResultID,
	}

	// 发送通知（异步，不阻塞）
	go func() {
		notificationService := biz.NewNotificationService(s.db, s.logger)
		sent, err := notificationService.SendAlertNotification(alertData)
		if err != nil {
			s.logger.Warn("发送告警通知失败",
				zap.Uint("alert_id", alert.ID),
				zap.Error(err),
			)
		} else if sent {
			// 只有实际发送了通知才更新通知时间和通知次数
			now := model.Now()
			s.db.Model(&model.Alert{}).Where("id = ?", alert.ID).Updates(map[string]interface{}{
				"last_notified_at": &now,
				"notify_count":     gorm.Expr("notify_count + 1"),
			})
			s.logger.Info("告警通知已发送",
				zap.Uint("alert_id", alert.ID),
				zap.String("host_id", alert.HostID),
				zap.String("rule_id", alert.RuleID),
			)
		} else {
			s.logger.Debug("告警无匹配的通知配置",
				zap.Uint("alert_id", alert.ID),
				zap.String("severity", alert.Severity),
			)
		}
	}()
}

// sendLoop 发送循环（向 Agent 发送命令）
func (s *Service) sendLoop(conn *Connection) {
	s.logger.Debug("sendLoop goroutine started", zap.String("agent_id", conn.AgentID))

	for {
		select {
		case <-conn.ctx.Done():
			s.logger.Debug("sendLoop goroutine stopping (context canceled)", zap.String("agent_id", conn.AgentID))
			return
		case cmd := <-conn.sendCh:
			hasCertBundle := cmd.CertificateBundle != nil
			hasAgentConfig := cmd.AgentConfig != nil

			s.logger.Debug("准备发送命令到Agent",
				zap.String("agent_id", conn.AgentID),
				zap.Bool("has_certificate_bundle", hasCertBundle),
				zap.Bool("has_agent_config", hasAgentConfig),
				zap.Int("task_count", len(cmd.Tasks)),
				zap.Int("config_count", len(cmd.Configs)),
			)

			if err := conn.stream.Send(cmd); err != nil {
				// 连接关闭导致的发送失败是正常现象，降为 Debug
				if conn.ctx.Err() != nil || status.Code(err) == codes.Canceled || status.Code(err) == codes.Unavailable {
					s.logger.Debug("Agent 连接已关闭，发送中止",
						zap.String("agent_id", conn.AgentID),
						zap.String("reason", err.Error()),
					)
				} else {
					s.logger.Error("发送命令失败",
						zap.Error(err),
						zap.String("agent_id", conn.AgentID),
						zap.String("error_type", fmt.Sprintf("%T", err)),
						zap.Bool("has_certificate_bundle", hasCertBundle),
						zap.Bool("has_agent_config", hasAgentConfig),
					)
				}
				return
			}

			s.logger.Debug("命令发送成功",
				zap.String("agent_id", conn.AgentID),
				zap.Bool("has_certificate_bundle", hasCertBundle),
			)
		}
	}
}

// registerConnection 注册连接
func (s *Service) registerConnection(agentID string, conn *Connection) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	// 如果同一 Agent 已有旧连接，取消旧连接的 context 使其 goroutine 立即退出
	// 避免旧连接的心跳数据覆盖新连接上报的版本等字段
	if oldConn, exists := s.connections[agentID]; exists && oldConn != conn {
		s.logger.Info("Agent 重连，取消旧连接",
			zap.String("agent_id", agentID),
			zap.String("old_version", oldConn.GetVersion()),
			zap.String("new_version", conn.Version),
		)
		oldConn.cancel()
	}

	s.connections[agentID] = conn
}

// checkAndSendAgentOnlineNotification 检查并发送 Agent 上线恢复通知
func (s *Service) checkAndSendAgentOnlineNotification(agentID string, conn *Connection) {
	// 查询主机信息
	var host model.Host
	if err := s.db.First(&host, "host_id = ?", agentID).Error; err != nil {
		// 主机不存在（首次注册），不发送恢复通知
		return
	}

	// 检查主机上次心跳时间，如果超过 3 分钟，说明之前离线
	offlineThreshold := 3 * time.Minute
	if host.LastHeartbeat == nil {
		// 首次注册，没有心跳记录，不发送恢复通知
		return
	}
	lastHeartbeat := host.LastHeartbeat.Time()
	if time.Since(lastHeartbeat) < offlineThreshold {
		// 主机最近有心跳，不算离线
		return
	}

	s.logger.Info("检测到 Agent 从离线状态恢复上线",
		zap.String("agent_id", agentID),
		zap.String("hostname", host.Hostname),
		zap.Time("last_heartbeat", lastHeartbeat),
		zap.Duration("offline_duration", time.Since(lastHeartbeat)),
	)

	// 自动解决离线告警
	s.resolveAgentOfflineAlert(agentID)

	// 获取主机 IP
	hostIP := ""
	if ipv4 := conn.GetIPv4(); len(ipv4) > 0 {
		hostIP = strings.Join(ipv4, ",")
	} else if len(host.IPv4) > 0 {
		hostIP = strings.Join(host.IPv4, ",")
	}

	// 构建上线数据
	onlineData := &biz.AgentOnlineData{
		HostID:       agentID,
		Hostname:     host.Hostname,
		IP:           hostIP,
		OSFamily:     host.OSFamily,
		OSVersion:    host.OSVersion,
		OnlineAt:     time.Now(),
		OfflineSince: lastHeartbeat,
	}

	// 发送上线恢复通知
	notificationService := biz.NewNotificationService(s.db, s.logger)
	if err := notificationService.SendAgentOnlineNotification(onlineData); err != nil {
		s.logger.Warn("发送 Agent 上线恢复通知失败",
			zap.String("agent_id", agentID),
			zap.Error(err),
		)
	}
}

// unregisterConnection 注销连接
func (s *Service) unregisterConnection(agentID string, connToRemove *Connection) {
	s.connMu.Lock()
	currentConn, exists := s.connections[agentID]
	// 只删除确实是当前连接的记录（指针比对，避免删除新连接）
	shouldDelete := exists && currentConn == connToRemove
	if shouldDelete {
		delete(s.connections, agentID)
	}
	s.connMu.Unlock()

	// 如果没有删除，说明已经有新连接，不需要发送离线通知
	if !shouldDelete {
		s.logger.Debug("跳过连接注销（已有新连接）",
			zap.String("agent_id", agentID),
			zap.Bool("exists", exists),
		)
		return
	}

	// Server 正在优雅关闭时，跳过离线通知（Agent 会在 Server 重启后自动重连）
	if s.shutdownFlag.Load() {
		s.logger.Info("服务关闭中，跳过离线通知", zap.String("agent_id", agentID))
		return
	}

	// 查询主机信息用于发送离线通知
	var host model.Host
	if err := s.db.First(&host, "host_id = ?", agentID).Error; err != nil {
		s.logger.Warn("查询主机信息失败，跳过离线通知", zap.String("agent_id", agentID), zap.Error(err))
	} else {
		// 发送 Agent 离线通知（异步，不阻塞）
		go func() {
			// 获取主机 IP（优先使用数据库中的 IP，如果没有则使用连接中的 IP）
			hostIP := ""
			if len(host.IPv4) > 0 {
				hostIP = strings.Join(host.IPv4, ",")
			} else if currentConn != nil && len(currentConn.IPv4) > 0 {
				hostIP = strings.Join(currentConn.IPv4, ",")
			}

			offlineData := &biz.AgentOfflineData{
				HostID:       host.HostID,
				Hostname:     host.Hostname,
				IP:           hostIP,
				OSFamily:     host.OSFamily,
				OSVersion:    host.OSVersion,
				LastOnlineAt: host.LastHeartbeat.Time(),
				OfflineAt:    time.Now(),
			}

			notificationService := biz.NewNotificationService(s.db, s.logger)
			if err := notificationService.SendAgentOfflineNotification(offlineData); err != nil {
				s.logger.Warn("发送 Agent 离线通知失败",
					zap.String("agent_id", agentID),
					zap.Error(err),
				)
			}
		}()
	}

	// 更新主机状态为离线
	s.db.Model(&model.Host{}).Where("host_id = ?", agentID).Update("status", model.HostStatusOffline)

	// 清理 Prometheus Gauge（避免 stale 指标残留）
	var offlineHost model.Host
	if err := s.db.Select("hostname").First(&offlineHost, "host_id = ?", agentID).Error; err == nil {
		metrics.Delete(agentID, offlineHost.Hostname)
	}

	// 创建 Agent 离线告警
	s.createAgentOfflineAlert(agentID)

	s.logger.Info("Agent 连接已注销", zap.String("agent_id", agentID))
}

// createAgentOfflineAlert 创建 Agent 离线告警
func (s *Service) createAgentOfflineAlert(agentID string) {
	// 查询主机信息
	var host model.Host
	if err := s.db.First(&host, "host_id = ?", agentID).Error; err != nil {
		return
	}

	now := model.Now()
	resultID := fmt.Sprintf("offline-%s", agentID)

	ip := ""
	if len(host.IPv4) > 0 {
		ip = host.IPv4[0]
	}
	title := fmt.Sprintf("Agent 离线: %s (%s)", host.Hostname, ip)
	description := fmt.Sprintf("主机 %s 的 Agent 已断开连接", host.Hostname)

	// 查找已有记录（包括已解决的）
	var existing model.Alert
	err := s.db.Where("result_id = ?", resultID).First(&existing).Error
	if err == nil {
		// 已有记录：重新激活（处理重复离线场景）
		s.db.Model(&existing).Updates(map[string]any{
			"status":       model.AlertStatusActive,
			"title":        title,
			"description":  description,
			"last_seen_at": now,
			"resolved_at":  nil,
			"resolved_by":  "",
		})
		s.logger.Info("已重新激活 Agent 离线告警", zap.String("agent_id", agentID), zap.Uint("alert_id", existing.ID))
	} else {
		alert := &model.Alert{
			ResultID:    resultID,
			HostID:      agentID,
			RuleID:      "agent_offline",
			Source:      model.AlertSourceAgent,
			Severity:    "high",
			Category:    "agent_offline",
			Title:       title,
			Description: description,
			Status:      model.AlertStatusActive,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
		if err := s.db.Create(alert).Error; err != nil {
			s.logger.Warn("创建 Agent 离线告警失败", zap.String("agent_id", agentID), zap.Error(err))
			return
		}
		s.logger.Info("已创建 Agent 离线告警", zap.String("agent_id", agentID), zap.Uint("alert_id", alert.ID))
	}
}

// resolveAgentOfflineAlert 解决 Agent 离线告警（Agent 上线时调用）
func (s *Service) resolveAgentOfflineAlert(agentID string) {
	now := model.Now()
	resultID := fmt.Sprintf("offline-%s", agentID)

	result := s.db.Model(&model.Alert{}).
		Where("result_id = ? AND status = ?", resultID, model.AlertStatusActive).
		Updates(map[string]any{
			"status":         model.AlertStatusResolved,
			"resolved_at":    &now,
			"resolved_by":    "system",
			"resolve_reason": "Agent 已恢复上线",
		})

	if result.RowsAffected > 0 {
		s.logger.Info("已自动解决 Agent 离线告警", zap.String("agent_id", agentID))
	}
}

// sendCertificateBundleIfNeeded 检查并下发证书包（如果Agent首次连接）
// 理论上，AgentCenter的证书申请后一直使用，然后分发给Agent用于通信
//
// PerAgentCert 开启时：为每台 agent 按 AgentID 在线签发独立证书（一机一证），取代下发全网共享证书。
// alreadyEnrolled=true（已持有 CN 匹配的单机证书）则跳过，避免每次重连重复签发。
func (s *Service) sendCertificateBundleIfNeeded(ctx context.Context, conn *Connection, hasClientCert, alreadyEnrolled bool) error {
	if s.cfg.MTLS.PerAgentCert {
		if alreadyEnrolled {
			s.logger.Debug("Agent 已持有单机证书，跳过下发", zap.String("agent_id", conn.AgentID))
			return nil
		}
		return s.signAndSendAgentCert(ctx, conn, hasClientCert)
	}

	// 读取Server端的证书文件
	caCertPath := s.cfg.MTLS.CACert
	// 客户端证书路径：从server_cert路径推导（例如 server.crt -> client.crt）
	// 如果server_cert是 "certs/server.crt"，则client_cert是 "certs/client.crt"
	serverCertPath := s.cfg.MTLS.ServerCert
	clientCertPath := serverCertPath
	if len(serverCertPath) > 0 {
		// 替换文件名：server.crt -> client.crt, server.key -> client.key
		clientCertPath = strings.Replace(serverCertPath, "server.crt", "client.crt", 1)
		clientCertPath = strings.Replace(clientCertPath, "server.key", "client.crt", 1)
	}
	clientKeyPath := strings.Replace(serverCertPath, "server.crt", "client.key", 1)
	clientKeyPath = strings.Replace(clientKeyPath, "server.key", "client.key", 1)

	s.logger.Debug("检查是否需要下发证书包",
		zap.String("agent_id", conn.AgentID),
		zap.String("ca_cert_path", caCertPath),
		zap.String("client_cert_path", clientCertPath),
		zap.String("client_key_path", clientKeyPath),
	)

	// 读取CA证书（用于Agent验证Server）
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("读取CA证书失败: %w", err)
	}

	// 读取客户端证书（Agent使用）
	clientCert, err := os.ReadFile(clientCertPath)
	if err != nil {
		return fmt.Errorf("读取客户端证书失败: %w", err)
	}

	// 读取客户端密钥（Agent使用）
	clientKey, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return fmt.Errorf("读取客户端密钥失败: %w", err)
	}

	// 构建证书包
	certBundle := &grpcProto.CertificateBundle{
		CaCert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}

	// 构建命令
	cmd := &grpcProto.Command{
		CertificateBundle: certBundle,
	}

	s.logger.Info("下发证书包到Agent",
		zap.String("agent_id", conn.AgentID),
		zap.Int("ca_cert_size", len(caCert)),
		zap.Int("client_cert_size", len(clientCert)),
		zap.Int("client_key_size", len(clientKey)),
	)

	// 发送证书包
	select {
	case conn.sendCh <- cmd:
		s.logger.Info("证书包已发送到Agent", zap.String("agent_id", conn.AgentID))
		return nil
	case <-conn.ctx.Done():
		return fmt.Errorf("连接已关闭: %s", conn.AgentID)
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("发送队列已满: %s", conn.AgentID)
	}
}

// buildPluginDownloadURLs 构建插件下载URL（处理相对路径）
// 优先从系统配置读取后端地址，确保与 Agent 更新使用相同的 URL
func (s *Service) buildPluginDownloadURLs(originalURLs []string, pluginName string) []string {
	downloadURLs := make([]string, 0, len(originalURLs))
	for _, urlStr := range originalURLs {
		// 如果URL已经是HTTP/HTTPS URL，直接使用
		if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
			downloadURLs = append(downloadURLs, urlStr)
			continue
		}

		if strings.HasPrefix(urlStr, "file://") {
			s.logger.Warn("检测到已废弃的 file:// 插件下载地址，跳过下发",
				zap.String("plugin_name", pluginName),
				zap.String("download_url", urlStr))
			continue
		}

		// 相对路径
		relativePath := urlStr

		// 构建完整 URL（使用相对路径）
		// 优先级：1.系统配置的 backend_url > 2.gRPC Host > 3.localhost
		var baseURL string

		// 优先级1: 从数据库获取后端接口地址配置（与 Agent 更新保持一致）
		var config model.SystemConfig
		if err := s.db.Where("`key` = ? AND category = ?", "site_config", "site").First(&config).Error; err == nil {
			var siteConfig model.SiteConfig
			if err := json.Unmarshal([]byte(config.Value), &siteConfig); err == nil && siteConfig.BackendURL != "" {
				backendURL := strings.TrimSuffix(siteConfig.BackendURL, "/")
				baseURL = backendURL
				s.logger.Debug("使用系统配置的后端地址构建插件下载URL",
					zap.String("source", "system_config"),
					zap.String("backend_url", backendURL),
					zap.String("plugin_name", pluginName))
			}
		}

		// 优先级2: 使用 gRPC Host
		if baseURL == "" {
			httpPort := s.cfg.Server.HTTP.Port
			grpcHost := s.cfg.Server.GRPC.Host
			if grpcHost != "0.0.0.0" && grpcHost != "" {
				baseURL = fmt.Sprintf("http://%s:%d", grpcHost, httpPort)
				s.logger.Debug("使用 gRPC Host 构建插件下载URL",
					zap.String("source", "grpc_host"),
					zap.String("grpc_host", grpcHost),
					zap.Int("http_port", httpPort),
					zap.String("plugin_name", pluginName))
			} else {
				// 优先级3: localhost（仅用于开发环境）
				baseURL = fmt.Sprintf("http://localhost:%d", httpPort)
				s.logger.Warn("未配置后端接口地址且 gRPC Host 为 0.0.0.0，使用 localhost（仅用于开发环境）",
					zap.String("source", "localhost_fallback"),
					zap.String("plugin_name", pluginName),
					zap.Int("http_port", httpPort))
			}
		}

		// 构建完整URL
		if strings.HasPrefix(relativePath, "/") {
			downloadURLs = append(downloadURLs, baseURL+relativePath)
		} else {
			downloadURLs = append(downloadURLs, baseURL+"/"+relativePath)
		}

		s.logger.Debug("插件下载URL构建完成",
			zap.String("plugin_name", pluginName),
			zap.String("original_url", urlStr),
			zap.String("download_url", downloadURLs[len(downloadURLs)-1]))
	}
	return downloadURLs
}

func (s *Service) pluginConfigUsesManagerDownload(pc model.PluginConfig, downloadURLs []string) bool {
	managerPath := fmt.Sprintf("/api/v1/plugins/download/%s", pc.Name)
	for _, urlStr := range downloadURLs {
		if strings.HasPrefix(urlStr, "/") {
			return true
		}
		if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
			if strings.Contains(urlStr, managerPath) {
				return true
			}
			if s.cfg != nil && s.cfg.Plugins.BaseURL != "" {
				expectedPrefix := strings.TrimRight(s.cfg.Plugins.BaseURL, "/") + "/"
				if strings.HasPrefix(urlStr, expectedPrefix) {
					return true
				}
			}
		}
	}
	return false
}

func (s *Service) pluginPackageExists(pc model.PluginConfig) bool {
	if strings.TrimSpace(pc.Version) == "" {
		return false
	}

	var component model.Component
	if err := s.db.Where("name = ? AND category = ?", pc.Name, model.ComponentCategoryPlugin).First(&component).Error; err != nil {
		return false
	}

	var version model.ComponentVersion
	if err := s.db.Where("component_id = ? AND version = ?", component.ID, pc.Version).First(&version).Error; err != nil {
		return false
	}

	var pkg model.ComponentPackage
	if err := s.db.Where("version_id = ? AND pkg_type = ? AND enabled = ?", version.ID, model.PackageTypeBinary, true).
		Order("CASE WHEN arch = 'amd64' THEN 0 ELSE 1 END").
		First(&pkg).Error; err != nil {
		return false
	}

	info, err := os.Stat(pkg.FilePath)
	return err == nil && !info.IsDir()
}

func (s *Service) resolvePluginDelivery(pc model.PluginConfig) ([]string, string) {
	downloadURLs := s.buildPluginDownloadURLs([]string(pc.DownloadURLs), pc.Name)
	if len(downloadURLs) == 0 {
		return nil, pc.SHA256
	}

	if s.pluginConfigUsesManagerDownload(pc, downloadURLs) && !s.pluginPackageExists(pc) {
		// 服务端无组件包,仍下发 config: Agent 端若有本地 cache + 可执行可继续使用.
		// 仅 warn 提醒管理员补上传, 避免新装 Agent 拉不到.
		s.logger.Warn("插件组件包不存在,仍下发(依赖 Agent 本地 cache)",
			zap.String("plugin", pc.Name),
			zap.String("version", pc.Version))
	}

	return downloadURLs, pc.SHA256
}

// sendPluginConfigsIfNeeded 下发插件配置给 Agent
func (s *Service) sendPluginConfigsIfNeeded(ctx context.Context, conn *Connection, runtimeType model.RuntimeType) error {
	// 从数据库查询启用的插件配置
	var pluginConfigs []model.PluginConfig
	if err := s.db.Where("enabled = ?", true).Find(&pluginConfigs).Error; err != nil {
		return fmt.Errorf("查询插件配置失败: %w", err)
	}

	if len(pluginConfigs) == 0 {
		s.logger.Debug("没有启用的插件配置", zap.String("agent_id", conn.AgentID))
		return nil
	}

	// 转换为 gRPC Config 格式，并处理相对URL
	var configs []*grpcProto.Config
	for _, pc := range pluginConfigs {
		// RuntimeTypes 为空 = 兼容旧数据，全平台发
		if len(pc.RuntimeTypes) > 0 && !containsString([]string(pc.RuntimeTypes), string(runtimeType)) {
			s.logger.Debug("插件不适用于当前运行时，跳过",
				zap.String("plugin", pc.Name),
				zap.String("runtime_type", string(runtimeType)),
				zap.Strings("plugin_runtime_types", []string(pc.RuntimeTypes)),
			)
			continue
		}

		downloadURLs, sha256 := s.resolvePluginDelivery(pc)
		if len(downloadURLs) == 0 {
			continue
		}

		config := &grpcProto.Config{
			Name:         pc.Name,
			Type:         string(pc.Type),
			Version:      pc.Version,
			Sha256:       sha256,
			Signature:    pc.Signature,
			DownloadUrls: downloadURLs,
			Detail:       pc.Detail,
		}
		configs = append(configs, config)
	}

	// 构建命令
	cmd := &grpcProto.Command{
		Configs: configs,
	}

	s.logger.Info("下发插件配置到Agent",
		zap.String("agent_id", conn.AgentID),
		zap.Int("plugin_count", len(configs)),
	)

	// 发送插件配置
	select {
	case conn.sendCh <- cmd:
		s.logger.Info("插件配置已发送到Agent",
			zap.String("agent_id", conn.AgentID),
			zap.Int("plugin_count", len(configs)),
		)
		return nil
	case <-conn.ctx.Done():
		return fmt.Errorf("连接已关闭: %s", conn.AgentID)
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("发送队列已满: %s", conn.AgentID)
	}
}

// SendCommand 向指定 Agent 发送命令（供其他模块调用）
func (s *Service) SendCommand(agentID string, cmd *grpcProto.Command) error {
	s.connMu.RLock()
	conn, ok := s.connections[agentID]
	s.connMu.RUnlock()

	if !ok {
		return fmt.Errorf("agent 未连接: %s", agentID)
	}

	select {
	case conn.sendCh <- cmd:
		return nil
	case <-conn.ctx.Done():
		return fmt.Errorf("连接已关闭: %s", agentID)
	default:
		return fmt.Errorf("发送队列已满: %s", agentID)
	}
}

// SendDependencyInstall 向指定 Agent 发送依赖安装命令
func (s *Service) SendDependencyInstall(agentID string, name, action, version, requestID, downloadURL string) error {
	cmd := &grpcProto.Command{
		DependencyInstall: &grpcProto.DependencyInstall{
			Name:        name,
			Action:      action,
			Version:     version,
			RequestId:   requestID,
			DownloadUrl: downloadURL,
		},
	}
	return s.SendCommand(agentID, cmd)
}

// BroadcastPluginConfigs 向所有在线 Agent 广播插件配置（用于推送更新）
// 返回成功发送的 Agent 数量和失败的 Agent 列表
func (s *Service) BroadcastPluginConfigs(ctx context.Context) (int, []string, error) {
	// 从数据库查询启用的插件配置
	var pluginConfigs []model.PluginConfig
	if err := s.db.Where("enabled = ?", true).Find(&pluginConfigs).Error; err != nil {
		return 0, nil, fmt.Errorf("查询插件配置失败: %w", err)
	}

	if len(pluginConfigs) == 0 {
		s.logger.Info("没有启用的插件配置，跳过广播")
		return 0, nil, nil
	}

	// 获取所有在线连接
	s.connMu.RLock()
	connections := make([]*Connection, 0, len(s.connections))
	for _, conn := range s.connections {
		connections = append(connections, conn)
	}
	s.connMu.RUnlock()

	if len(connections) == 0 {
		s.logger.Info("没有在线的 Agent，跳过广播")
		return 0, nil, nil
	}

	s.logger.Info("开始广播插件配置到所有在线 Agent",
		zap.Int("agent_count", len(connections)),
		zap.Int("plugin_count", len(pluginConfigs)))

	// 向每个连接发送配置（根据其 runtime_type 过滤）
	successCount := 0
	var failedAgents []string

	for _, conn := range connections {
		// 获取该 Agent 的 runtime_type
		runtimeType := s.getAgentRuntimeType(conn.AgentID)

		// 为该 Agent 过滤插件配置
		var configs []*grpcProto.Config
		for _, pc := range pluginConfigs {
			// RuntimeTypes 为空 = 兼容旧数据，全平台发
			if len(pc.RuntimeTypes) > 0 && !containsString([]string(pc.RuntimeTypes), string(runtimeType)) {
				continue
			}

			downloadURLs, sha256 := s.resolvePluginDelivery(pc)
			if len(downloadURLs) == 0 {
				continue
			}

			config := &grpcProto.Config{
				Name:         pc.Name,
				Type:         string(pc.Type),
				Version:      pc.Version,
				Sha256:       sha256,
				Signature:    pc.Signature,
				DownloadUrls: downloadURLs,
				Detail:       pc.Detail,
			}
			configs = append(configs, config)
		}

		// 如果该 Agent 没有适用的插件，跳过
		if len(configs) == 0 {
			s.logger.Debug("该 Agent 没有适用的插件配置，跳过",
				zap.String("agent_id", conn.AgentID),
				zap.String("runtime_type", string(runtimeType)))
			continue
		}

		// 构建命令
		cmd := &grpcProto.Command{
			Configs: configs,
		}

		select {
		case conn.sendCh <- cmd:
			successCount++
			s.logger.Debug("插件配置已发送到 Agent",
				zap.String("agent_id", conn.AgentID),
				zap.Int("plugin_count", len(configs)))
		case <-conn.ctx.Done():
			failedAgents = append(failedAgents, conn.AgentID)
			s.logger.Warn("发送插件配置失败：连接已关闭",
				zap.String("agent_id", conn.AgentID))
		default:
			failedAgents = append(failedAgents, conn.AgentID)
			s.logger.Warn("发送插件配置失败：队列已满",
				zap.String("agent_id", conn.AgentID))
		}
	}

	s.logger.Info("插件配置广播完成",
		zap.Int("success_count", successCount),
		zap.Int("failed_count", len(failedAgents)))

	return successCount, failedAgents, nil
}

// BroadcastPluginConfigsByName 只广播指定名称的插件配置（差异广播）
// 分批发送，每批 20 个 Agent 后暂停 200ms，避免所有 Agent 同时下载
func (s *Service) BroadcastPluginConfigsByName(ctx context.Context, pluginNames []string) (int, []string, error) {
	if len(pluginNames) == 0 {
		return 0, nil, nil
	}

	// 从数据库查询指定的插件配置
	var pluginConfigs []model.PluginConfig
	if err := s.db.Where("enabled = ? AND name IN ?", true, pluginNames).Find(&pluginConfigs).Error; err != nil {
		return 0, nil, fmt.Errorf("查询插件配置失败: %w", err)
	}

	if len(pluginConfigs) == 0 {
		return 0, nil, nil
	}

	// 获取所有在线连接
	s.connMu.RLock()
	connections := make([]*Connection, 0, len(s.connections))
	for _, conn := range s.connections {
		connections = append(connections, conn)
	}
	s.connMu.RUnlock()

	if len(connections) == 0 {
		return 0, nil, nil
	}

	s.logger.Info("开始差异广播插件配置",
		zap.Int("agent_count", len(connections)),
		zap.Strings("plugins", pluginNames))

	// 分批发送，每批 broadcastBatchSize 个 Agent
	const broadcastBatchSize = 20
	const broadcastBatchDelay = 200 * time.Millisecond
	successCount := 0
	var failedAgents []string

	for i, conn := range connections {
		if i > 0 && i%broadcastBatchSize == 0 {
			time.Sleep(broadcastBatchDelay)
		}

		runtimeType := s.getAgentRuntimeType(conn.AgentID)

		var configs []*grpcProto.Config
		for _, pc := range pluginConfigs {
			if len(pc.RuntimeTypes) > 0 && !containsString([]string(pc.RuntimeTypes), string(runtimeType)) {
				continue
			}

			downloadURLs, sha256 := s.resolvePluginDelivery(pc)
			if len(downloadURLs) == 0 {
				continue
			}

			config := &grpcProto.Config{
				Name:         pc.Name,
				Type:         string(pc.Type),
				Version:      pc.Version,
				Sha256:       sha256,
				Signature:    pc.Signature,
				DownloadUrls: downloadURLs,
				Detail:       pc.Detail,
			}
			configs = append(configs, config)
		}

		if len(configs) == 0 {
			continue
		}

		cmd := &grpcProto.Command{
			Configs: configs,
		}

		select {
		case conn.sendCh <- cmd:
			successCount++
		case <-conn.ctx.Done():
			failedAgents = append(failedAgents, conn.AgentID)
		default:
			failedAgents = append(failedAgents, conn.AgentID)
		}
	}

	s.logger.Info("差异广播完成",
		zap.Int("success_count", successCount),
		zap.Int("failed_count", len(failedAgents)),
		zap.Strings("plugins", pluginNames))

	return successCount, failedAgents, nil
}

// GracefulShutdown 标记服务正在关闭，后续连接断开不再发送离线通知
func (s *Service) GracefulShutdown() {
	s.shutdownFlag.Store(true)
	s.logger.Info("Transfer 服务进入优雅关闭，后续断连不发送离线通知")
}

// StopMetricsBuffer 停止指标缓冲区的后台刷写，在服务关闭时调用以刷写剩余数据
func (s *Service) StopMetricsBuffer() {
	if s.metricsBuffer != nil {
		s.metricsBuffer.Stop()
	}
}

// GetOnlineAgentCount 获取在线 Agent 数量
func (s *Service) GetOnlineAgentCount() int {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	return len(s.connections)
}

// GetOnlineAgentIDs 获取所有在线 Agent ID 列表
func (s *Service) GetOnlineAgentIDs() []string {
	s.connMu.RLock()
	defer s.connMu.RUnlock()

	ids := make([]string, 0, len(s.connections))
	for agentID := range s.connections {
		ids = append(ids, agentID)
	}
	return ids
}

// AgentDetail 是 /conn/list 返回的单个 Agent 连接信息
type AgentDetail struct {
	AgentID  string   `json:"agent_id"`
	Hostname string   `json:"hostname"`
	IPv4     []string `json:"ipv4"`
	IPv6     []string `json:"ipv6"`
	Version  string   `json:"version"`
	LastSeen string   `json:"last_seen"` // RFC3339
}

// GetOnlineAgentDetails 获取所有在线 Agent 的详细连接信息
func (s *Service) GetOnlineAgentDetails() []AgentDetail {
	s.connMu.RLock()
	defer s.connMu.RUnlock()

	details := make([]AgentDetail, 0, len(s.connections))
	for _, conn := range s.connections {
		conn.mu.RLock()
		d := AgentDetail{
			AgentID:  conn.AgentID,
			Hostname: conn.Hostname,
			IPv4:     conn.IPv4,
			IPv6:     conn.IPv6,
			Version:  conn.Version,
			LastSeen: conn.LastSeen.Format(time.RFC3339),
		}
		conn.mu.RUnlock()
		details = append(details, d)
	}
	return details
}

// handleFixResult 处理基线修复结果
func (s *Service) handleFixResult(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	// 解析 EncodedRecord.data 为 bridge.Record
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析 Record 失败: %w", err)
	}

	// 从 Payload 中提取字段
	if bridgeRecord.Data == nil {
		return fmt.Errorf("Record.Data 为空")
	}
	fields := bridgeRecord.Data.Fields

	// 提取必要字段（复合主键 task_id + host_id + rule_id，不再需要 result_id）
	fixTaskID := fields["fix_task_id"]
	hostID := conn.AgentID
	ruleID := fields["rule_id"]
	status := fields["status"]
	command := fields["command"]
	output := fields["output"]
	errorMsg := fields["error_msg"]
	message := fields["message"]

	// 解析时间戳
	timestamp := time.Unix(0, record.Timestamp)
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// 转换为 FixResultStatus
	var resultStatus model.FixResultStatus
	switch status {
	case "success":
		resultStatus = model.FixResultStatusSuccess
	case "failed":
		resultStatus = model.FixResultStatusFailed
	case "skipped":
		resultStatus = model.FixResultStatusSkipped
	default:
		resultStatus = model.FixResultStatusFailed
	}

	// 创建 FixResult（复合主键 task_id + host_id + rule_id）
	fixResult := &model.FixResult{
		TaskID:   fixTaskID,
		HostID:   hostID,
		RuleID:   ruleID,
		Status:   resultStatus,
		Command:  command,
		Output:   output,
		ErrorMsg: errorMsg,
		Message:  message,
		FixedAt:  model.ToLocalTime(timestamp),
	}

	// 保存到数据库
	if err := s.db.Create(fixResult).Error; err != nil {
		return fmt.Errorf("保存修复结果失败: %w", err)
	}

	s.logger.Debug("修复结果已保存",
		zap.String("agent_id", conn.AgentID),
		zap.String("fix_task_id", fixTaskID),
		zap.String("rule_id", ruleID),
		zap.String("status", string(resultStatus)),
	)

	// 修复成功时，更新原始扫描结果为 pass（防止重复修复）
	if resultStatus == model.FixResultStatusSuccess {
		if err := s.db.Model(&model.ScanResult{}).
			Where("host_id = ? AND rule_id = ? AND status IN ?", hostID, ruleID, []string{"fail", "error"}).
			Update("status", model.ResultStatusPass).Error; err != nil {
			s.logger.Warn("更新扫描结果状态失败",
				zap.String("host_id", hostID),
				zap.String("rule_id", ruleID),
				zap.Error(err),
			)
		}
	}

	// 更新任务统计（跳过 _SERVICE_RESTART 等内部结果，不计入修复统计）
	if strings.HasPrefix(ruleID, "_") {
		s.logger.Debug("跳过内部结果的任务统计",
			zap.String("rule_id", ruleID),
			zap.String("fix_task_id", fixTaskID),
		)
		return nil
	}

	var task model.FixTask
	if err := s.db.Where("task_id = ?", fixTaskID).First(&task).Error; err == nil {
		// 更新成功/失败计数
		updates := make(map[string]interface{})
		if resultStatus == model.FixResultStatusSuccess {
			updates["success_count"] = gorm.Expr("success_count + 1")
		} else if resultStatus == model.FixResultStatusFailed {
			updates["failed_count"] = gorm.Expr("failed_count + 1")
		}

		// 计算进度
		totalProcessed := task.SuccessCount + task.FailedCount + 1 // +1 for current result
		if task.TotalCount > 0 {
			progress := int(float64(totalProcessed) / float64(task.TotalCount) * 100)
			if progress > 100 {
				progress = 100
			}
			updates["progress"] = progress
		}

		if err := s.db.Model(&task).Updates(updates).Error; err != nil {
			s.logger.Error("更新修复任务统计失败",
				zap.String("fix_task_id", fixTaskID),
				zap.Error(err),
			)
		}
	}

	return nil
}

// handleFixTaskComplete 处理修复任务完成信号
func (s *Service) handleFixTaskComplete(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	// 解析 EncodedRecord.data 为 bridge.Record
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析修复任务完成信号失败: %w", err)
	}

	// 从 Payload 中提取字段
	if bridgeRecord.Data == nil {
		return fmt.Errorf("Record.Data 为空")
	}
	fields := bridgeRecord.Data.Fields

	taskID := fields["task_id"]
	fixTaskID := fields["fix_task_id"]
	status := fields["status"]
	resultCount := fields["result_count"]
	completedAt := fields["completed_at"]

	if fixTaskID == "" {
		s.logger.Warn("修复任务完成信号缺少 fix_task_id", zap.String("agent_id", conn.AgentID))
		return nil
	}

	s.logger.Info("收到修复任务完成信号",
		zap.String("agent_id", conn.AgentID),
		zap.String("task_id", taskID),
		zap.String("fix_task_id", fixTaskID),
		zap.String("status", status),
		zap.String("result_count", resultCount),
		zap.String("completed_at", completedAt),
	)

	// 更新主机状态为 completed
	now := model.Now()

	// 先查询是否存在该记录
	var existingStatus model.FixTaskHostStatus
	if err := s.db.Where("task_id = ? AND host_id = ?", fixTaskID, conn.AgentID).First(&existingStatus).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logger.Warn("未找到修复任务主机状态记录，无法更新",
				zap.String("fix_task_id", fixTaskID),
				zap.String("host_id", conn.AgentID),
			)
			// 继续处理，不返回错误
		} else {
			s.logger.Error("查询修复任务主机状态失败",
				zap.String("fix_task_id", fixTaskID),
				zap.String("host_id", conn.AgentID),
				zap.Error(err),
			)
			// 继续处理，不返回错误
		}
	} else {
		// 记录更新前的状态
		s.logger.Debug("准备更新修复任务主机状态",
			zap.String("fix_task_id", fixTaskID),
			zap.String("host_id", conn.AgentID),
			zap.String("current_status", existingStatus.Status),
		)

		// 执行更新
		result := s.db.Model(&model.FixTaskHostStatus{}).
			Where("task_id = ? AND host_id = ?", fixTaskID, conn.AgentID).
			Updates(map[string]interface{}{
				"status":       model.FixTaskHostStatusCompleted,
				"completed_at": &now,
			})

		if result.Error != nil {
			s.logger.Error("更新修复任务主机状态失败",
				zap.String("fix_task_id", fixTaskID),
				zap.String("host_id", conn.AgentID),
				zap.Error(result.Error),
			)
			// 继续处理，不返回错误
		} else if result.RowsAffected == 0 {
			s.logger.Warn("更新修复任务主机状态未影响任何记录",
				zap.String("fix_task_id", fixTaskID),
				zap.String("host_id", conn.AgentID),
			)
		} else {
			s.logger.Info("成功更新修复任务主机状态为已完成",
				zap.String("fix_task_id", fixTaskID),
				zap.String("host_id", conn.AgentID),
				zap.Int64("rows_affected", result.RowsAffected),
			)
		}
	}

	// 查询任务
	var task model.FixTask
	if err := s.db.Where("task_id = ?", fixTaskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logger.Warn("修复任务不存在", zap.String("fix_task_id", fixTaskID))
			return nil
		}
		return fmt.Errorf("查询修复任务失败: %w", err)
	}

	// 如果任务已经完成或失败，不再处理
	if task.Status == model.FixTaskStatusCompleted || task.Status == model.FixTaskStatusFailed {
		s.logger.Debug("修复任务已完成/失败，忽略完成信号",
			zap.String("fix_task_id", fixTaskID),
			zap.String("status", string(task.Status)),
		)
		return nil
	}

	// 统计已完成的主机数（通过查询不同的 host_id）
	var completedHosts int64
	s.db.Model(&model.FixResult{}).
		Where("task_id = ?", fixTaskID).
		Distinct("host_id").
		Count(&completedHosts)

	s.logger.Info("修复任务主机完成统计",
		zap.String("fix_task_id", fixTaskID),
		zap.Int64("completed_hosts", completedHosts),
		zap.Int("total_hosts", len(task.HostIDs)),
	)

	// 检查是否所有主机都已完成
	if int(completedHosts) >= len(task.HostIDs) {
		// 所有主机都已返回结果，标记任务为 completed
		now := model.Now()
		updates := map[string]interface{}{
			"status":       model.FixTaskStatusCompleted,
			"completed_at": &now,
			"progress":     100,
		}

		if err := s.db.Model(&task).Updates(updates).Error; err != nil {
			return fmt.Errorf("更新修复任务状态失败: %w", err)
		}

		s.logger.Info("修复任务所有主机都已完成，状态更新为 completed",
			zap.String("fix_task_id", fixTaskID),
			zap.Int64("completed_hosts", completedHosts),
			zap.Int("total_hosts", len(task.HostIDs)),
		)
	}

	return nil
}

// handleFIMEvent 处理 FIM 事件（DataType 6001）
func (s *Service) handleFIMEvent(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析 FIM 事件失败: %w", err)
	}

	if bridgeRecord.Data == nil {
		return fmt.Errorf("FIM 事件 Record.Data 为空")
	}
	fields := bridgeRecord.Data.Fields

	eventID := fields["event_id"]
	taskID := fields["task_id"]
	filePath := fields["file_path"]
	changeType := fields["change_type"]
	severity := fields["severity"]
	category := fields["category"]
	changeDetailStr := fields["change_detail"]
	detectedAtStr := fields["detected_at"]

	if eventID == "" || taskID == "" {
		s.logger.Warn("FIM 事件缺少必要字段",
			zap.String("agent_id", conn.AgentID),
			zap.String("event_id", eventID),
			zap.String("task_id", taskID),
		)
		return nil
	}

	// 解析 change_detail JSON
	var changeDetail model.ChangeDetail
	if changeDetailStr != "" {
		_ = json.Unmarshal([]byte(changeDetailStr), &changeDetail)
	}

	// 解析检测时间
	detectedAt := model.Now()
	if detectedAtStr != "" {
		if t, err := time.Parse(time.RFC3339, detectedAtStr); err == nil {
			detectedAt = model.ToLocalTime(t)
		}
	}

	fimEvent := &model.FIMEvent{
		EventID:      eventID,
		HostID:       conn.AgentID,
		Hostname:     conn.GetHostname(),
		TaskID:       taskID,
		FilePath:     filePath,
		ChangeType:   changeType,
		ChangeDetail: changeDetail,
		Severity:     severity,
		Category:     category,
		DetectedAt:   detectedAt,
		Status:       "pending",
	}

	if err := s.db.Create(fimEvent).Error; err != nil {
		return fmt.Errorf("保存 FIM 事件失败: %w", err)
	}

	// 递增任务的 total_events 计数
	s.db.Model(&model.FIMTask{}).
		Where("task_id = ?", taskID).
		Update("total_events", gorm.Expr("total_events + 1"))

	s.logger.Debug("FIM 事件已保存",
		zap.String("event_id", eventID),
		zap.String("host_id", conn.AgentID),
		zap.String("file_path", filePath),
		zap.String("change_type", changeType),
		zap.String("severity", severity),
	)

	return nil
}

// handleFIMTaskCompletion 处理 FIM 任务完成信号（DataType 6002）
func (s *Service) handleFIMTaskCompletion(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析 FIM 任务完成信号失败: %w", err)
	}

	if bridgeRecord.Data == nil {
		return fmt.Errorf("FIM 完成信号 Record.Data 为空")
	}
	fields := bridgeRecord.Data.Fields

	taskID := fields["task_id"]
	taskStatus := fields["status"]
	errorMessage := fields["error_message"]
	completedAtStr := fields["completed_at"]
	totalEntries, _ := strconv.Atoi(fields["total_entries"])
	addedCount, _ := strconv.Atoi(fields["added_count"])
	removedCount, _ := strconv.Atoi(fields["removed_count"])
	changedCount, _ := strconv.Atoi(fields["changed_count"])
	runTimeSec, _ := strconv.Atoi(fields["run_time_sec"])

	if taskID == "" {
		s.logger.Warn("FIM 完成信号缺少 task_id",
			zap.String("agent_id", conn.AgentID))
		return nil
	}

	s.logger.Info("收到 FIM 任务完成信号",
		zap.String("agent_id", conn.AgentID),
		zap.String("task_id", taskID),
		zap.String("status", taskStatus),
		zap.Int("total_entries", totalEntries),
		zap.Int("changed_count", changedCount),
	)

	// 更新主机状态
	now := model.Now()
	hostStatus := "completed"
	if taskStatus == "failed" {
		hostStatus = "failed"
	}

	hostUpdates := map[string]interface{}{
		"status":        hostStatus,
		"total_entries": totalEntries,
		"added_count":   addedCount,
		"removed_count": removedCount,
		"changed_count": changedCount,
		"run_time_sec":  runTimeSec,
		"error_message": errorMessage,
		"completed_at":  &now,
	}

	result := s.db.Model(&model.FIMTaskHostStatus{}).
		Where("task_id = ? AND host_id = ? AND status = ?",
			taskID, conn.AgentID, "dispatched").
		Updates(hostUpdates)

	if result.Error != nil {
		s.logger.Error("更新 FIM 主机状态失败",
			zap.String("task_id", taskID),
			zap.String("host_id", conn.AgentID),
			zap.Error(result.Error))
	}

	// 递增已完成主机数
	s.db.Model(&model.FIMTask{}).
		Where("task_id = ?", taskID).
		Update("completed_host_count",
			gorm.Expr("completed_host_count + 1"))

	// 检查是否所有主机都已完成
	var task model.FIMTask
	if err := s.db.Where("task_id = ?", taskID).
		First(&task).Error; err != nil {
		return fmt.Errorf("查询 FIM 任务失败: %w", err)
	}

	if task.CompletedHostCount >= task.DispatchedHostCount &&
		task.DispatchedHostCount > 0 {
		completedAt := model.Now()
		_ = completedAtStr // 使用服务端时间
		s.db.Model(&task).Updates(map[string]interface{}{
			"status":       "completed",
			"completed_at": &completedAt,
		})
		s.logger.Info("FIM 任务所有主机已完成",
			zap.String("task_id", taskID),
			zap.Int("completed", task.CompletedHostCount),
			zap.Int("dispatched", task.DispatchedHostCount),
		)
	}

	return nil
}

// handleFIMBaselineSnapshot 处理 FIM 基线快照（DataType 6004）
// Agent 首次扫描后上报文件快照，服务端创建待审批基线
func (s *Service) handleFIMBaselineSnapshot(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析 FIM 基线快照失败: %w", err)
	}

	if bridgeRecord.Data == nil {
		return fmt.Errorf("FIM 基线快照 Record.Data 为空")
	}
	fields := bridgeRecord.Data.Fields

	policyID := fields["policy_id"]
	taskID := fields["task_id"]
	snapshotStr := fields["snapshot"]
	entryCount, _ := strconv.Atoi(fields["entry_count"])

	if policyID == "" || snapshotStr == "" {
		s.logger.Warn("FIM 基线快照缺少必要字段",
			zap.String("agent_id", conn.AgentID),
			zap.String("policy_id", policyID))
		return nil
	}

	// 解析快照 JSON
	type snapshotEntry struct {
		SHA256 string `json:"sha256,omitempty"`
		Size   int64  `json:"size"`
		Mode   string `json:"mode,omitempty"`
		UID    uint32 `json:"uid"`
		GID    uint32 `json:"gid"`
		MTime  int64  `json:"mtime"`
	}
	var snapshot map[string]snapshotEntry
	if err := json.Unmarshal([]byte(snapshotStr), &snapshot); err != nil {
		return fmt.Errorf("解析基线快照 JSON 失败: %w", err)
	}

	s.logger.Info("收到 FIM 基线快照",
		zap.String("agent_id", conn.AgentID),
		zap.String("policy_id", policyID),
		zap.Int("entry_count", entryCount))

	// 创建基线记录
	baseline := &model.FIMBaseline{
		PolicyID:   policyID,
		HostID:     conn.AgentID,
		Hostname:   conn.GetHostname(),
		Version:    1,
		Status:     "pending",
		EntryCount: len(snapshot),
		TaskID:     taskID,
		CreatedAt:  model.Now(),
		UpdatedAt:  model.Now(),
	}

	err := s.db.Transaction(func(tx *gorm.DB) error {
		// 删除同策略+主机的旧 pending 基线
		var oldBaselines []model.FIMBaseline
		tx.Where("policy_id = ? AND host_id = ? AND status = ?",
			policyID, conn.AgentID, "pending").Find(&oldBaselines)
		for _, old := range oldBaselines {
			tx.Where("baseline_id = ?", old.ID).Delete(&model.FIMBaselineEntry{})
			tx.Delete(&old)
		}

		// 创建新基线
		if err := tx.Create(baseline).Error; err != nil {
			return fmt.Errorf("创建基线记录失败: %w", err)
		}

		// 批量写入条目
		entries := make([]model.FIMBaselineEntry, 0, len(snapshot))
		for filePath, entry := range snapshot {
			entries = append(entries, model.FIMBaselineEntry{
				BaselineID: baseline.ID,
				FilePath:   filePath,
				SHA256:     entry.SHA256,
				FileSize:   entry.Size,
				FileMode:   entry.Mode,
				UID:        entry.UID,
				GID:        entry.GID,
				MTime:      entry.MTime,
			})
		}

		// 分批插入（每批 500 条）
		batchSize := 500
		for i := 0; i < len(entries); i += batchSize {
			end := i + batchSize
			if end > len(entries) {
				end = len(entries)
			}
			if err := tx.Create(entries[i:end]).Error; err != nil {
				return fmt.Errorf("批量写入基线条目失败: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("保存 FIM 基线快照失败: %w", err)
	}

	s.logger.Info("FIM 基线快照已保存，等待审批",
		zap.String("policy_id", policyID),
		zap.String("host_id", conn.AgentID),
		zap.Uint("baseline_id", baseline.ID),
		zap.Int("entries", len(snapshot)))

	return nil
}

// isAlertWhitelisted 检查告警是否命中白名单
func (s *Service) isAlertWhitelisted(ruleID, hostID, category, severity string) bool {
	var whitelists []model.AlertWhitelist
	if err := s.db.Find(&whitelists).Error; err != nil {
		s.logger.Warn("查询告警白名单失败，跳过白名单检查", zap.Error(err))
		return false
	}
	for i := range whitelists {
		if whitelists[i].Matches(ruleID, hostID, category, severity) {
			return true
		}
	}
	return false
}

// containsString 检查字符串切片中是否包含指定字符串
func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// handleScanResult 处理 Scanner 扫描结果（DataType 7001，MySQL 直写路径）
func (s *Service) handleScanResult(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析 Scanner 结果失败: %w", err)
	}
	fields := bridgeRecord.Data.Fields

	var taskID uint
	if v, err := strconv.ParseUint(fields["task_id"], 10, 64); err == nil {
		taskID = uint(v)
	}
	fileSize, _ := strconv.ParseInt(fields["file_size"], 10, 64)

	result := &model.AntivirusScanResult{
		TaskID:     taskID,
		HostID:     conn.AgentID,
		Hostname:   conn.GetHostname(),
		IP:         strings.Join(conn.GetIPv4(), ","),
		FilePath:   fields["file_path"],
		ThreatName: fields["threat_name"],
		ThreatType: fields["threat_type"],
		Severity:   fields["severity"],
		FileHash:   fields["file_hash"],
		FileSize:   fileSize,
		Action:     "detected",
		DetectedAt: model.LocalTime(time.Now()),
	}

	if err := s.db.Create(result).Error; err != nil {
		return fmt.Errorf("写入扫描结果失败: %w", err)
	}

	s.db.Model(&model.AntivirusScanTask{}).
		Where("id = ?", taskID).
		UpdateColumn("threat_count", gorm.Expr("threat_count + 1"))

	return nil
}

// handleScanTaskComplete 处理 Scanner 任务完成（DataType 7002，MySQL 直写路径）
func (s *Service) handleScanTaskComplete(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析 Scanner 完成信号失败: %w", err)
	}
	fields := bridgeRecord.Data.Fields

	var taskID uint
	if v, err := strconv.ParseUint(fields["task_id"], 10, 64); err == nil {
		taskID = uint(v)
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.AntivirusScanTask{}).
			Where("id = ?", taskID).
			UpdateColumn("scanned_hosts", gorm.Expr("scanned_hosts + 1")).Error; err != nil {
			return err
		}

		var task model.AntivirusScanTask
		if err := tx.First(&task, taskID).Error; err != nil {
			return err
		}

		if task.ScannedHosts >= task.TotalHosts && task.Status != "completed" {
			now := model.LocalTime(time.Now())
			return tx.Model(&task).Updates(map[string]interface{}{
				"status":      "completed",
				"finished_at": &now,
			}).Error
		}
		return nil
	})
}

// handleQuarantineResult 处理 Scanner 隔离/删除结果（DataType 7004，MySQL 直写路径）
func (s *Service) handleQuarantineResult(ctx context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析隔离结果失败: %w", err)
	}
	fields := bridgeRecord.Data.Fields

	if fields["action"] == "quarantine" && fields["status"] == "success" {
		file := &model.QuarantineFile{
			HostID:         conn.AgentID,
			Hostname:       conn.GetHostname(),
			IP:             strings.Join(conn.GetIPv4(), ","),
			OriginalPath:   fields["file_path"],
			QuarantinePath: fields["quarantine_path"],
			FilePermission: fields["file_permission"],
			FileOwner:      fields["file_owner"],
			Status:         "quarantined",
			QuarantinedAt:  model.LocalTime(time.Now()),
		}
		return s.db.Create(file).Error
	}
	return nil
}

// handleRemediationResult 处理漏洞修复任务结果（DataType 9001）
func (s *Service) handleRemediationResult(_ context.Context, record *grpcProto.EncodedRecord, conn *Connection) error {
	bridgeRecord := &bridge.Record{}
	if err := proto.Unmarshal(record.Data, bridgeRecord); err != nil {
		return fmt.Errorf("解析修复结果失败: %w", err)
	}

	if bridgeRecord.Data == nil {
		return fmt.Errorf("Record.Data 为空")
	}
	fields := bridgeRecord.Data.Fields

	executor := biz.NewRemediationExecutor(s.db, s.logger)
	return executor.HandleResult(conn.AgentID, fields)
}

// getAgentRuntimeType 获取 Agent 的运行时类型
func (s *Service) getAgentRuntimeType(agentID string) model.RuntimeType {
	var host model.Host
	if err := s.db.Select("runtime_type").Where("host_id = ?", agentID).First(&host).Error; err != nil {
		// 新主机默认 vm
		return model.RuntimeTypeVM
	}
	return host.RuntimeType
}
