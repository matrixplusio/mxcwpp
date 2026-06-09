// Package transport 提供 gRPC 传输功能（双向流）
package transport

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	grpcLib "google.golang.org/grpc"

	"github.com/imkerbos/mxsec-platform/api/proto/bridge"
	"github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/agent/buffer"
	"github.com/imkerbos/mxsec-platform/internal/agent/cache"
	"github.com/imkerbos/mxsec-platform/internal/agent/config"
	"github.com/imkerbos/mxsec-platform/internal/agent/connection"
	"github.com/imkerbos/mxsec-platform/internal/agent/dependency"
	"github.com/imkerbos/mxsec-platform/internal/agent/updater"
	"github.com/imkerbos/mxsec-platform/internal/agent/wal"
	_ "github.com/imkerbos/mxsec-platform/internal/common/compressor" // 注册 Snappy 压缩器
)

// sendInterval 批量发送间隔（与 Elkeid 一致）
const sendInterval = 100 * time.Millisecond

// agentMetadata 缓存 Agent 元信息（由心跳更新，sendData 构建 PackagedData 时使用）
type agentMetadata struct {
	hostname     string
	intranetIPv4 []string
	extranetIPv4 []string
	intranetIPv6 []string
	extranetIPv6 []string
	version      string
	product      string
}

// Manager 是传输管理器
type Manager struct {
	cfg            *config.Config
	logger         *zap.Logger
	connMgr        *connection.Manager
	agentID        string
	ringBuffer     *buffer.RingBuffer                               // 环形缓冲区（替代 channel）
	pluginConfigCh chan []*grpc.Config                              // 插件配置通道
	agentUpdateCh  chan *grpc.AgentUpdate                           // Agent 更新通道
	taskCh         chan *grpc.Task                                  // 任务通道（兼容旧代码）
	taskChannels   map[string]chan *grpc.Task                       // 按插件名称分发的任务通道
	taskChMu       sync.RWMutex                                     // 任务通道锁
	onConfigUpdate func(*grpc.AgentConfig, *grpc.CertificateBundle) // 配置更新回调 (agentConfig, certBundle)
	onTaskCancel   func(token string)                               // 任务取消回调
	cacheMgr       *cache.Manager                                   // 缓存管理器
	eventWAL       *wal.WAL                                         // EDR 事件 WAL（断网兜底）
	depMgr         *dependency.Manager                              // 依赖管理器
	agentMeta      agentMetadata                                    // Agent 元信息缓存
	agentMetaMu    sync.RWMutex                                     // 元信息读写锁
	isConnected    bool                                             // 连接状态
	connectedMu    sync.RWMutex
}

// NewManager 创建新的传输管理器
func NewManager(cfg *config.Config, logger *zap.Logger, connMgr *connection.Manager, agentID string) (*Manager, error) {
	// 创建缓存管理器
	cacheDir := cfg.GetWorkDir() + "/cache"
	cacheMgr, err := cache.NewManager(cacheDir, 100*1024*1024, 7*24*time.Hour, logger) // 100MB, 7天
	if err != nil {
		return nil, fmt.Errorf("failed to create cache manager: %w", err)
	}

	// 创建 EDR 事件 WAL（断网时兜底缓冲）
	walDir := cfg.GetWorkDir() + "/wal"
	eventWAL, err := wal.New(walDir, wal.DefaultMaxSize, logger.Named("wal"))
	if err != nil {
		logger.Warn("failed to create WAL, EDR events may be lost on disconnect", zap.Error(err))
	}

	return &Manager{
		cfg:            cfg,
		logger:         logger,
		connMgr:        connMgr,
		agentID:        agentID,
		ringBuffer:     buffer.New(),
		pluginConfigCh: make(chan []*grpc.Config, 10),
		agentUpdateCh:  make(chan *grpc.AgentUpdate, 10),
		taskCh:         make(chan *grpc.Task, 100),
		taskChannels:   make(map[string]chan *grpc.Task),
		cacheMgr:       cacheMgr,
		eventWAL:       eventWAL,
		depMgr:         dependency.NewManager(logger),
		isConnected:    false,
	}, nil
}

// SetConfigUpdateCallback 设置配置更新回调
func (m *Manager) SetConfigUpdateCallback(callback func(*grpc.AgentConfig, *grpc.CertificateBundle)) {
	m.onConfigUpdate = callback
}

// SetTaskCancelCallback 设置任务取消回调
func (m *Manager) SetTaskCancelCallback(callback func(token string)) {
	m.onTaskCancel = callback
}

// Startup 启动传输模块（创建新的管理器）
func Startup(ctx context.Context, wg *sync.WaitGroup, cfg *config.Config, logger *zap.Logger, connMgr *connection.Manager, agentID string) {
	mgr, err := NewManager(cfg, logger, connMgr, agentID)
	if err != nil {
		logger.Error("failed to create transport manager", zap.Error(err))
		wg.Done()
		return
	}
	StartupWithManager(ctx, wg, mgr)
}

// StartupWithManager 启动传输模块（使用已创建的管理器）
func StartupWithManager(ctx context.Context, wg *sync.WaitGroup, mgr *Manager) {
	defer wg.Done()

	// 启动缓存清理循环
	go mgr.cacheMgr.StartCleanupLoop(ctx)

	// 启动缓存重试循环
	go mgr.retryCachedData(ctx)

	mgr.logger.Info("transport module starting, attempting to connect...")

	// 指数退避重试配置
	retryDelay := 1 * time.Second     // 初始延迟1秒
	maxRetryDelay := 10 * time.Second // 最大延迟10秒
	retryCount := 0

	for {
		select {
		case <-ctx.Done():
			mgr.logger.Info("transport module shutting down")
			return
		default:
			// 获取连接
			mgr.logger.Debug("attempting to get connection",
				zap.Int("retry_count", retryCount),
				zap.Duration("retry_delay", retryDelay),
			)
			conn, err := mgr.connMgr.GetConnection(ctx)
			if err != nil {
				mgr.setConnected(false)
				retryCount++
				mgr.logger.Error("failed to get connection",
					zap.Error(err),
					zap.Int("retry_count", retryCount),
					zap.Duration("retry_delay", retryDelay),
				)
				// P2-3: 指数退避 + ±30% jitter 防雷鸣群 (1w 主机同时重连冲击 AgentCenter)
				time.Sleep(withJitter(retryDelay))
				retryDelay = retryDelay * 2
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
				continue
			}

			// 连接成功，重置重试计数和延迟
			retryCount = 0
			retryDelay = 1 * time.Second
			mgr.logger.Debug("connection obtained successfully")

			// 创建 gRPC 客户端（启用 Snappy 流压缩）
			mgr.logger.Debug("creating gRPC Transfer client with snappy compression")
			client := grpc.NewTransferClient(conn)
			stream, err := client.Transfer(ctx, grpcLib.UseCompressor("snappy"))
			if err != nil {
				mgr.setConnected(false)
				retryCount++
				mgr.logger.Error("failed to create stream",
					zap.Error(err),
					zap.Int("retry_count", retryCount),
					zap.Duration("retry_delay", retryDelay),
				)
				// P2-3: jitter 退避
				time.Sleep(withJitter(retryDelay))
				retryDelay = retryDelay * 2
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
				continue
			}

			mgr.setConnected(true)
			mgr.logger.Info("gRPC stream established successfully",
				zap.String("agent_id", mgr.agentID),
			)

			// 连接建立后，先发送缓存的数据
			if err := mgr.sendCachedData(ctx, stream); err != nil {
				mgr.logger.Warn("failed to send cached data", zap.Error(err))
			}

			// WAL 重放：将断网期间持久化的 EDR 事件重发到 Server
			if mgr.eventWAL != nil && mgr.eventWAL.HasData() {
				mgr.logger.Info("replaying WAL events after reconnection",
					zap.Int64("wal_size", mgr.eventWAL.Size()))
				if err := mgr.replayWAL(stream); err != nil {
					mgr.logger.Warn("WAL replay failed", zap.Error(err))
				}
			}

			// 启动发送和接收 goroutine
			subWg := &sync.WaitGroup{}
			subWg.Add(2)

			go mgr.sendData(ctx, subWg, stream)
			go mgr.receiveCommands(ctx, subWg, stream)

			// 等待连接断开
			subWg.Wait()
			mgr.setConnected(false)
			mgr.logger.Warn("gRPC stream disconnected, reconnecting...",
				zap.String("agent_id", mgr.agentID),
			)
			// 连接断开后，重置重试延迟为初始值（快速重连）
			retryDelay = 1 * time.Second
			retryCount = 0
		}
	}
}

// sendWithTimeout 带超时的发送，防止 gRPC Send 因 server 反压永久阻塞
func (m *Manager) sendWithTimeout(stream grpc.Transfer_TransferClient, data *grpc.PackagedData, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- stream.Send(data)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("send timeout after %s", timeout)
	}
}

// sendData 定时批量发送数据到 Server（100ms ticker 驱动）
func (m *Manager) sendData(ctx context.Context, wg *sync.WaitGroup, stream grpc.Transfer_TransferClient) {
	defer wg.Done()

	m.logger.Debug("sendData goroutine started (ticker mode)",
		zap.Duration("interval", sendInterval),
	)

	sendTimeout := 30 * time.Second
	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Debug("sendData goroutine stopping (context canceled)")
			return
		case <-ticker.C:
			records := m.ringBuffer.ReadAll()
			if len(records) == 0 {
				continue
			}

			// 批量构建 PackagedData，附加缓存的 Agent 元信息
			data := m.buildPackagedData(records)

			m.logger.Debug("sending batched data to server",
				zap.String("agent_id", data.AgentId),
				zap.Int("record_count", len(data.Records)),
			)

			if err := m.sendWithTimeout(stream, data, sendTimeout); err != nil {
				m.logger.Error("failed to send data, caching for retry",
					zap.Error(err),
					zap.String("error_type", fmt.Sprintf("%T", err)),
					zap.Int("record_count", len(data.Records)),
				)
				// 发送失败，将数据写入本地缓存（重连后重发）而非直接丢弃
				if m.cacheMgr != nil {
					if cacheErr := m.cacheMgr.Put(data); cacheErr != nil {
						m.logger.Error("failed to cache unsent data",
							zap.Error(cacheErr),
							zap.Int("lost_records", len(data.Records)),
						)
					} else {
						m.logger.Info("unsent data cached for retry",
							zap.Int("record_count", len(data.Records)),
						)
					}
				}
				return
			}

			m.logger.Debug("batched data sent successfully",
				zap.Int("record_count", len(data.Records)),
				zap.String("agent_id", data.AgentId),
			)
		}
	}
}

// buildPackagedData 使用缓存的 Agent 元信息构建批量 PackagedData
func (m *Manager) buildPackagedData(records []*grpc.EncodedRecord) *grpc.PackagedData {
	m.agentMetaMu.RLock()
	meta := m.agentMeta
	m.agentMetaMu.RUnlock()

	return &grpc.PackagedData{
		Records:      records,
		AgentId:      m.agentID,
		Hostname:     meta.hostname,
		IntranetIpv4: meta.intranetIPv4,
		ExtranetIpv4: meta.extranetIPv4,
		IntranetIpv6: meta.intranetIPv6,
		ExtranetIpv6: meta.extranetIPv6,
		Version:      meta.version,
		Product:      meta.product,
	}
}

// receiveCommands 接收 Server 命令
func (m *Manager) receiveCommands(ctx context.Context, wg *sync.WaitGroup, stream grpc.Transfer_TransferClient) {
	defer wg.Done()

	m.logger.Debug("receiveCommands goroutine started, waiting for commands...")

	for {
		select {
		case <-ctx.Done():
			m.logger.Debug("receiveCommands goroutine stopping (context canceled)")
			return
		default:
			m.logger.Debug("waiting to receive command from server...")
			cmd, err := stream.Recv()
			if err != nil {
				if err != context.Canceled {
					m.logger.Error("failed to receive command",
						zap.Error(err),
						zap.String("error_type", fmt.Sprintf("%T", err)),
					)
				} else {
					m.logger.Debug("receiveCommands canceled by context")
				}
				return
			}

			m.logger.Debug("received command from server",
				zap.Int("task_count", len(cmd.Tasks)),
				zap.Int("config_count", len(cmd.Configs)),
				zap.Bool("has_agent_config", cmd.AgentConfig != nil),
				zap.Bool("has_certificate_bundle", cmd.CertificateBundle != nil),
			)

			// 处理 Agent 配置更新
			if cmd.AgentConfig != nil {
				m.logger.Info("received agent config update from server",
					zap.Int32("heartbeat_interval", cmd.AgentConfig.HeartbeatInterval),
					zap.String("work_dir", cmd.AgentConfig.WorkDir),
					zap.String("product", cmd.AgentConfig.Product),
					zap.String("version", cmd.AgentConfig.Version),
				)
				// 通知配置管理器更新配置（通过回调函数）
				if m.onConfigUpdate != nil {
					m.onConfigUpdate(cmd.AgentConfig, nil)
				} else {
					m.logger.Warn("agent config update callback not set")
				}
			}

			// 处理证书包更新（首次连接时）
			if cmd.CertificateBundle != nil {
				caCertLen := len(cmd.CertificateBundle.CaCert)
				clientCertLen := len(cmd.CertificateBundle.ClientCert)
				clientKeyLen := len(cmd.CertificateBundle.ClientKey)
				m.logger.Info("received certificate bundle from server",
					zap.Int("ca_cert_size", caCertLen),
					zap.Int("client_cert_size", clientCertLen),
					zap.Int("client_key_size", clientKeyLen),
				)
				// 通知配置管理器更新证书（通过回调函数）
				if m.onConfigUpdate != nil {
					m.onConfigUpdate(nil, cmd.CertificateBundle)
				} else {
					m.logger.Warn("certificate bundle update callback not set")
				}
			}

			// 处理插件配置更新
			if len(cmd.Configs) > 0 {
				m.logger.Info("received plugin configs from server", zap.Int("count", len(cmd.Configs)))
				select {
				case m.pluginConfigCh <- cmd.Configs:
				default:
					m.logger.Warn("plugin config channel full, dropping configs")
				}
			}

			// 处理 Agent 更新命令
			if cmd.AgentUpdate != nil {
				m.logger.Info("received agent update command from server",
					zap.String("version", cmd.AgentUpdate.Version),
					zap.String("download_url", cmd.AgentUpdate.DownloadUrl),
					zap.String("sha256", cmd.AgentUpdate.Sha256),
					zap.String("pkg_type", cmd.AgentUpdate.PkgType),
					zap.String("arch", cmd.AgentUpdate.Arch),
					zap.Bool("force", cmd.AgentUpdate.Force),
				)
				select {
				case m.agentUpdateCh <- cmd.AgentUpdate:
					m.logger.Debug("agent update command dispatched to channel")
				default:
					m.logger.Warn("agent update channel full, dropping update command")
				}
			}

			// 处理 Agent 重启命令
			if cmd.AgentRestart {
				m.logger.Info("received agent restart command from server")
				updater.RestartAgent()
			}

			// 处理依赖安装命令
			if cmd.DependencyInstall != nil {
				di := cmd.DependencyInstall
				m.logger.Info("received dependency install command",
					zap.String("name", di.Name),
					zap.String("action", di.Action),
					zap.String("version", di.Version),
					zap.String("request_id", di.RequestId),
					zap.String("download_url", di.DownloadUrl))
				go m.handleDependencyInstall(di)
			}

			// 处理任务（按插件名称分发到对应通道）
			if len(cmd.Tasks) > 0 {
				// Debug level: cron task 流量大(precheck cron 单 host 单 tick 可达 200 条),
				// Info 会触发 journald rate-limit 抑制其他关键日志。详见 follow-up 修复说明。
				m.logger.Debug("received tasks from server", zap.Int("count", len(cmd.Tasks)))
				for _, task := range cmd.Tasks {
					// DataType=9900 是任务取消信号，不分发到插件，直接回调
					if task.DataType == 9900 {
						m.logger.Info("received task cancel signal",
							zap.String("token", task.Token))
						if m.onTaskCancel != nil {
							m.onTaskCancel(task.Token)
						}
						continue
					}

					// 优先尝试分发到专用通道
					m.taskChMu.RLock()
					ch, ok := m.taskChannels[task.ObjectName]
					m.taskChMu.RUnlock()

					if ok {
						// 找到专用通道，发送到该通道
						select {
						case ch <- task:
							m.logger.Debug("task dispatched to plugin channel",
								zap.String("object_name", task.ObjectName),
								zap.String("token", task.Token))
						default:
							m.logger.Warn("plugin task channel full, dropping task",
								zap.String("object_name", task.ObjectName))
						}
					} else {
						// 没有专用通道，发送到通用通道（兼容旧代码）
						select {
						case m.taskCh <- task:
							m.logger.Debug("task dispatched to general channel",
								zap.String("object_name", task.ObjectName))
						default:
							m.logger.Warn("task channel full, dropping task",
								zap.String("object_name", task.ObjectName))
						}
					}
				}
			}

		}
	}
}

// SendHeartbeat 发送心跳数据
// 将心跳记录写入 ringBuffer（内部数据，满溢时覆盖最旧数据），同时缓存 Agent 元信息
func (m *Manager) SendHeartbeat(data *grpc.PackagedData) error {
	// 检查连接状态
	if !m.IsConnected() {
		// 连接未建立，直接丢弃（心跳是状态快照，旧数据无价值，重连后会发最新的）
		m.logger.Debug("connection not established, dropping heartbeat (will send fresh data after reconnect)",
			zap.String("agent_id", data.AgentId),
		)
		return nil
	}

	// 缓存 Agent 元信息（sendData 构建 PackagedData 时使用）
	m.agentMetaMu.Lock()
	m.agentMeta = agentMetadata{
		hostname:     data.Hostname,
		intranetIPv4: data.IntranetIpv4,
		extranetIPv4: data.ExtranetIpv4,
		intranetIPv6: data.IntranetIpv6,
		extranetIPv6: data.ExtranetIpv6,
		version:      data.Version,
		product:      data.Product,
	}
	m.agentMetaMu.Unlock()

	// 将心跳记录写入 ringBuffer（使用 WriteRecord，满溢时覆盖 buf[0]）
	for _, rec := range data.Records {
		m.ringBuffer.WriteRecord(rec)
	}

	return nil
}

// GetPluginConfigChannel 获取插件配置通道
func (m *Manager) GetPluginConfigChannel() <-chan []*grpc.Config {
	return m.pluginConfigCh
}

// GetAgentUpdateChannel 获取 Agent 更新通道
func (m *Manager) GetAgentUpdateChannel() <-chan *grpc.AgentUpdate {
	return m.agentUpdateCh
}

// SendPluginData 发送插件数据到 Server
// 序列化为 EncodedRecord 后写入 ringBuffer（插件数据，满溢时丢弃新数据）
func (m *Manager) SendPluginData(pluginName string, record *bridge.Record) error {
	// 序列化 Record
	recordData, err := proto.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal plugin record: %w", err)
	}

	// 构建 EncodedRecord 并写入 ringBuffer
	encodedRecord := &grpc.EncodedRecord{
		DataType:  record.DataType,
		Timestamp: record.Timestamp,
		Data:      recordData,
	}

	if !m.ringBuffer.WriteEncodedRecord(encodedRecord) {
		// Ring buffer full: EDR events (3000-3099) go to WAL, others are dropped.
		if m.eventWAL != nil && record.DataType >= 3000 && record.DataType <= 3099 {
			if !m.eventWAL.Write(encodedRecord) {
				m.logger.Warn("WAL full, dropping EDR event",
					zap.Int32("data_type", record.DataType))
			}
		} else {
			m.logger.Warn("ring buffer full, dropping plugin data",
				zap.String("plugin", pluginName))
		}
	}

	return nil
}

// sendCachedData 连接建立后清空旧缓存（心跳和资产数据都是状态快照，旧数据无价值，重放会导致旧版本号覆盖 DB）
func (m *Manager) sendCachedData(ctx context.Context, stream grpc.Transfer_TransferClient) error {
	purgedCount := 0
	for {
		_, filePath, err := m.cacheMgr.Get()
		if err != nil {
			m.logger.Error("failed to get cached data during purge", zap.Error(err))
			break
		}
		if filePath == "" {
			break // 没有缓存数据了
		}
		if err := m.cacheMgr.Remove(filePath); err != nil {
			m.logger.Warn("failed to remove cached file during purge", zap.String("file", filePath), zap.Error(err))
		}
		purgedCount++
	}

	if purgedCount > 0 {
		m.logger.Debug("purged stale cached data after reconnect (will send fresh heartbeat instead)",
			zap.Int("purged_count", purgedCount),
		)
	}

	return nil
}

// replayWAL replays persisted EDR events from the WAL after reconnection.
func (m *Manager) replayWAL(stream grpc.Transfer_TransferClient) error {
	sendTimeout := 30 * time.Second

	return m.eventWAL.Replay(100, func(records []*grpc.EncodedRecord) error {
		data := m.buildPackagedData(records)
		if err := m.sendWithTimeout(stream, data, sendTimeout); err != nil {
			return fmt.Errorf("WAL replay send: %w", err)
		}
		m.logger.Debug("WAL batch sent",
			zap.Int("records", len(records)))
		return nil
	})
}

// retryCachedData 定期清理残留缓存（正常情况下 sendCachedData 已清空，这里做兜底）
func (m *Manager) retryCachedData(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !m.IsConnected() {
				continue
			}

			// 清理残留缓存文件
			purgedCount := 0
			for i := 0; i < 50; i++ {
				_, filePath, err := m.cacheMgr.Get()
				if err != nil {
					break
				}
				if filePath == "" {
					break
				}
				if err := m.cacheMgr.Remove(filePath); err != nil {
					m.logger.Warn("failed to remove stale cached file", zap.String("file", filePath), zap.Error(err))
				}
				purgedCount++
			}
			if purgedCount > 0 {
				m.logger.Debug("purged stale cached data in retry loop", zap.Int("purged_count", purgedCount))
			}
		}
	}
}

// setConnected 设置连接状态
func (m *Manager) setConnected(connected bool) {
	m.connectedMu.Lock()
	defer m.connectedMu.Unlock()
	m.isConnected = connected
}

// IsConnected 返回连接状态
func (m *Manager) IsConnected() bool {
	m.connectedMu.RLock()
	defer m.connectedMu.RUnlock()
	return m.isConnected
}

// GetTaskChannel 获取任务通道（供插件管理器使用）
func (m *Manager) GetTaskChannel() <-chan *grpc.Task {
	return m.taskCh
}

// RegisterTaskChannel 为指定插件注册专用任务通道
// 总是创建新 channel，避免旧 sendTask 的 defer UnregisterTaskChannel close 到新 channel
func (m *Manager) RegisterTaskChannel(pluginName string) <-chan *grpc.Task {
	m.taskChMu.Lock()
	defer m.taskChMu.Unlock()

	ch := make(chan *grpc.Task, 100)
	m.taskChannels[pluginName] = ch
	m.logger.Debug("registered task channel for plugin", zap.String("plugin_name", pluginName))
	return ch
}

// UnregisterTaskChannel 注销插件的任务通道
// 仅从 map 中删除，不 close channel（让 GC 回收），避免 close 到新 channel 的风险
func (m *Manager) UnregisterTaskChannel(pluginName string) {
	m.taskChMu.Lock()
	defer m.taskChMu.Unlock()

	if _, ok := m.taskChannels[pluginName]; ok {
		delete(m.taskChannels, pluginName)
		m.logger.Debug("unregistered task channel for plugin", zap.String("plugin_name", pluginName))
	}
}

// GetTaskChannelForPlugin 获取指定插件的任务通道
func (m *Manager) GetTaskChannelForPlugin(pluginName string) <-chan *grpc.Task {
	m.taskChMu.RLock()
	defer m.taskChMu.RUnlock()

	if ch, ok := m.taskChannels[pluginName]; ok {
		return ch
	}
	return nil
}

// SendTaskToPlugin 向指定插件的任务通道发送任务（用于任务重试）
func (m *Manager) SendTaskToPlugin(pluginName string, task *grpc.Task) error {
	m.taskChMu.RLock()
	ch, ok := m.taskChannels[pluginName]
	m.taskChMu.RUnlock()

	if !ok {
		return fmt.Errorf("task channel not found for plugin: %s", pluginName)
	}

	select {
	case ch <- task:
		m.logger.Debug("task sent to plugin channel",
			zap.String("plugin", pluginName),
			zap.String("token", task.Token))
		return nil
	default:
		return fmt.Errorf("task channel full for plugin: %s", pluginName)
	}
}

// DataType 常量：依赖安装结果
const dataTypeDependencyInstallResult int32 = 9100

// handleDependencyInstall 处理依赖安装命令并上报结果
func (m *Manager) handleDependencyInstall(di *grpc.DependencyInstall) {
	m.depMgr.BackendURL = di.DownloadUrl
	result := m.depMgr.Execute(di.Name, di.Action, di.Version)

	m.logger.Info("dependency install result",
		zap.String("name", di.Name),
		zap.String("action", di.Action),
		zap.Bool("success", result.Success),
		zap.String("message", result.Message))

	// 构建上报数据
	reportResult := &grpc.DependencyInstallResult{
		RequestId: di.RequestId,
		Name:      di.Name,
		Success:   result.Success,
		Message:   result.Message,
		Version:   result.Version,
	}

	data, err := proto.Marshal(reportResult)
	if err != nil {
		m.logger.Error("failed to marshal dependency install result", zap.Error(err))
		return
	}

	record := &grpc.EncodedRecord{
		DataType:  dataTypeDependencyInstallResult,
		Timestamp: time.Now().UnixNano(),
		Data:      data,
	}

	if !m.ringBuffer.WriteEncodedRecord(record) {
		m.logger.Warn("ring buffer full, dropping dependency install result")
	}
}
