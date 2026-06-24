// Package plugin 提供插件生命周期管理和 Pipe 通信功能
package plugin

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	"github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/agent/config"
	agentrt "github.com/matrixplusio/mxcwpp/internal/agent/runtime"
	"github.com/matrixplusio/mxcwpp/internal/agent/transport"
	"github.com/matrixplusio/mxcwpp/internal/common/fileutil"
	"github.com/matrixplusio/mxcwpp/internal/common/signing"
	"google.golang.org/protobuf/proto"
)

// Manager 是插件管理器
type Manager struct {
	cfg         *config.Config
	logger      *zap.Logger
	transport   *transport.Manager
	plugins     map[string]*Plugin // 插件名称 -> 插件实例
	mu          sync.RWMutex       // 保护 plugins map
	ctx         context.Context
	cancel      context.CancelFunc
	taskTracker *TaskTracker // 任务追踪器
}

// Plugin 表示一个插件实例
type Plugin struct {
	Config       *grpc.Config   // 插件配置
	cmd          *exec.Cmd      // 插件进程
	rx           *os.File       // 接收管道（Agent 从插件读取数据）
	tx           *os.File       // 发送管道（Agent 向插件写入任务）
	logWriter    io.WriteCloser // 日志写入器（支持日志轮转）
	workDir      string         // 插件工作目录
	status       Status         // 插件状态
	mu           sync.RWMutex   // 保护状态
	startTime    time.Time      // 启动时间
	lastPong     time.Time      // 最后一次收到插件 pong 的时间（用于健康检查）
	pingCh       chan struct{}  // 通知 sendTask 发送 ping
	stopCh       chan struct{}  // 停止信号
	logger       *zap.Logger
	restartCount int       // 连续重启计数（稳定运行 10min 后重置）
	dormantSince time.Time // 进入休眠的时间
	exitCode     int       // 最后退出码
}

// Status 是插件状态
type Status string

const (
	StatusStopped  Status = "stopped"
	StatusStarting Status = "starting"
	StatusRunning  Status = "running"
	StatusStopping Status = "stopping"
	StatusError    Status = "error"
	StatusDormant  Status = "dormant" // 依赖不可用，定期探测
)

// 插件退出码约定
const (
	ExitCodeNormal         = 0  // 正常退出
	ExitCodeCrash          = 1  // 崩溃（应重启）
	ExitCodeDepUnavailable = 10 // 依赖不可用（进入休眠）
)

// 心跳 DataType 常量
const (
	DataTypeHeartbeatPing int32 = 9000
	DataTypeHeartbeatPong int32 = 9001
)

// NewManager 创建新的插件管理器
func NewManager(cfg *config.Config, logger *zap.Logger, transportMgr *transport.Manager) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	// 创建任务追踪器
	taskTracker, err := NewTaskTracker(cfg.GetWorkDir(), logger)
	if err != nil {
		logger.Warn("failed to create task tracker, task recovery disabled", zap.Error(err))
	}

	mgr := &Manager{
		cfg:         cfg,
		logger:      logger,
		transport:   transportMgr,
		plugins:     make(map[string]*Plugin),
		ctx:         ctx,
		cancel:      cancel,
		taskTracker: taskTracker,
	}

	// 注册任务取消回调
	if taskTracker != nil {
		transportMgr.SetTaskCancelCallback(func(token string) {
			if err := taskTracker.MarkCancelled(token); err != nil {
				logger.Debug("cancel signal for unknown task", zap.String("token", token))
			}
		})
		go mgr.taskCleanupLoop()
	}

	return mgr
}

// Startup 启动插件管理模块（创建新的管理器）
func Startup(ctx context.Context, wg *sync.WaitGroup, cfg *config.Config, logger *zap.Logger, transportMgr *transport.Manager) {
	mgr := NewManager(cfg, logger, transportMgr)
	StartupWithManager(ctx, wg, mgr)
}

// StartupWithManager 启动插件管理模块（使用已创建的管理器）
func StartupWithManager(ctx context.Context, wg *sync.WaitGroup, mgr *Manager) {
	defer wg.Done()

	// 监听插件配置更新
	configCh := mgr.transport.GetPluginConfigChannel()
	if configCh == nil {
		mgr.logger.Warn("plugin config channel not available")
		return
	}

	mgr.logger.Info("plugin manager started")

	// 启动插件健康检查 watchdog
	go mgr.watchPlugins()

	// 监听配置更新和上下文取消
	for {
		select {
		case <-ctx.Done():
			mgr.logger.Info("plugin manager shutting down")
			mgr.ShutdownAll()
			return
		case configs := <-configCh:
			// 同步插件配置
			if err := mgr.SyncPlugins(ctx, configs); err != nil {
				mgr.logger.Error("failed to sync plugins", zap.Error(err))
			}
		}
	}
}

// SyncPlugins 同步插件配置（从 Server 接收的配置）
func (m *Manager) SyncPlugins(ctx context.Context, configs []*grpc.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 构建当前配置的插件名称集合
	configMap := make(map[string]*grpc.Config)
	for _, cfg := range configs {
		configMap[cfg.Name] = cfg
	}

	// 停止已删除的插件
	for name, plugin := range m.plugins {
		if _, exists := configMap[name]; !exists {
			m.logger.Info("stopping removed plugin", zap.String("name", name))
			if err := m.stopPlugin(plugin); err != nil {
				m.logger.Error("failed to stop plugin", zap.String("name", name), zap.Error(err))
			}
			delete(m.plugins, name)
		}
	}

	// 启动或更新插件
	for _, cfg := range configs {
		plugin, exists := m.plugins[cfg.Name]
		if !exists {
			// 新插件，启动它
			m.logger.Info("loading new plugin", zap.String("name", cfg.Name), zap.String("version", cfg.Version))
			newPlugin, err := m.loadPlugin(ctx, cfg)
			if err != nil {
				m.logger.Error("failed to load plugin", zap.String("name", cfg.Name), zap.Error(err))
				continue
			}
			m.plugins[cfg.Name] = newPlugin
		} else {
			// 检查是否需要更新（使用版本比较）
			needsUpdate := false
			if plugin.Config.Sha256 != cfg.Sha256 {
				needsUpdate = true
			} else {
				// 使用版本比较判断是否需要更新
				oldVersion, err1 := ParseVersion(plugin.Config.Version)
				newVersion, err2 := ParseVersion(cfg.Version)
				if err1 != nil || err2 != nil {
					// 版本解析失败，使用字符串比较
					if plugin.Config.Version != cfg.Version {
						needsUpdate = true
					}
				} else if newVersion.GreaterThan(oldVersion) {
					needsUpdate = true
				}
			}

			if needsUpdate {
				m.logger.Info("updating plugin", zap.String("name", cfg.Name),
					zap.String("old_version", plugin.Config.Version),
					zap.String("new_version", cfg.Version))
				// 备份旧二进制
				backupPath, backupErr := m.backupPlugin(cfg.Name)
				if backupErr != nil {
					m.logger.Warn("failed to backup plugin before update",
						zap.String("name", cfg.Name), zap.Error(backupErr))
				}
				// 停止旧插件
				if err := m.stopPlugin(plugin); err != nil {
					m.logger.Error("failed to stop old plugin", zap.String("name", cfg.Name), zap.Error(err))
					// 如果停止失败，尝试强制停止
					if plugin.cmd.Process != nil {
						_ = plugin.cmd.Process.Kill()
					}
				}
				// 等待一小段时间，确保进程完全退出
				time.Sleep(100 * time.Millisecond)
				// 启动新插件
				newPlugin, err := m.loadPlugin(ctx, cfg)
				if err != nil {
					m.logger.Error("failed to load updated plugin", zap.String("name", cfg.Name), zap.Error(err))
					// 更新失败，尝试从备份恢复二进制再回滚
					if backupPath != "" {
						if restoreErr := m.restoreFromBackup(cfg.Name); restoreErr != nil {
							m.logger.Error("failed to restore plugin from backup",
								zap.String("name", cfg.Name), zap.Error(restoreErr))
							continue
						}
					}
					if oldPlugin, loadErr := m.loadPlugin(ctx, plugin.Config); loadErr == nil {
						m.logger.Info("rolled back to previous plugin version", zap.String("name", cfg.Name))
						m.plugins[cfg.Name] = oldPlugin
					} else {
						m.logger.Error("failed to rollback plugin",
							zap.String("name", cfg.Name), zap.Error(loadErr))
					}
					continue
				}
				m.plugins[cfg.Name] = newPlugin
			} else {
				// 不需要更新，检查是否 dormant 需要唤醒
				plugin.mu.RLock()
				isDormant := plugin.status == StatusDormant
				plugin.mu.RUnlock()
				if isDormant {
					m.logger.Info("waking dormant plugin during sync", zap.String("name", cfg.Name))
					newPlugin, err := m.loadPlugin(ctx, cfg)
					if err != nil {
						plugin.mu.Lock()
						plugin.dormantSince = time.Now()
						plugin.mu.Unlock()
					} else {
						m.plugins[cfg.Name] = newPlugin
					}
				}
			}
		}
	}

	return nil
}

// loadPlugin 加载插件
func (m *Manager) loadPlugin(ctx context.Context, cfg *grpc.Config) (*Plugin, error) {
	// 1. 验证插件配置
	if err := m.validatePluginConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid plugin config: %w", err)
	}

	// 2. 准备插件工作目录
	workDir := filepath.Join(m.cfg.GetWorkDir(), "plugins", cfg.Name)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create work dir: %w", err)
	}

	// 3. 下载插件（如果不存在或签名不匹配）
	execPath, err := m.downloadPlugin(cfg, workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to download plugin: %w", err)
	}

	// 3.5 数据类插件（如 virus-database）：只需下载解压，不启动进程
	if cfg.Type == "virus-database" || execPath == workDir {
		m.logger.Info("data-only plugin synced (no process)",
			zap.String("name", cfg.Name),
			zap.String("version", cfg.Version),
			zap.String("path", workDir))
		plugin := &Plugin{
			Config:    cfg,
			workDir:   workDir,
			status:    StatusRunning,
			startTime: time.Now(),
			lastPong:  time.Now(),
			pingCh:    make(chan struct{}, 1),
			stopCh:    make(chan struct{}),
			logger:    m.logger.With(zap.String("plugin", cfg.Name)),
		}
		return plugin, nil
	}

	// 4. 创建 Pipe
	rx_r, rx_w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create rx pipe: %w", err)
	}

	tx_r, tx_w, err := os.Pipe()
	if err != nil {
		rx_r.Close()
		rx_w.Close()
		return nil, fmt.Errorf("failed to create tx pipe: %w", err)
	}

	// 5. 设置日志文件重定向（带轮转功能）
	// 从 Agent 日志文件路径提取目录，插件日志放在同级的 plugins 子目录
	agentLogFile := m.cfg.Local.Log.File
	if agentLogFile == "" {
		agentLogFile = "/var/log/mxcwpp-agent/agent.log" // 默认路径
	}
	logDir := filepath.Join(filepath.Dir(agentLogFile), "plugins")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		rx_r.Close()
		rx_w.Close()
		tx_r.Close()
		tx_w.Close()
		return nil, fmt.Errorf("failed to create plugin log dir: %w", err)
	}

	// 配置日志轮转（与 Agent 保持一致：按天轮转，保留7天）
	logFile := filepath.Join(logDir, fmt.Sprintf("%s.log", cfg.Name))
	maxAge := 7 * 24 * time.Hour // 保留7天
	if m.cfg.Local.Log.MaxAge > 0 {
		maxAge = time.Duration(m.cfg.Local.Log.MaxAge) * 24 * time.Hour
	}

	logWriter, err := rotatelogs.New(
		logFile+".%Y-%m-%d",                       // 轮转后的文件名格式：{plugin}.log.YYYY-MM-DD
		rotatelogs.WithLinkName(logFile),          // 当前日志文件链接
		rotatelogs.WithMaxAge(maxAge),             // 保留时间（默认7天）
		rotatelogs.WithRotationTime(24*time.Hour), // 每24小时轮转一次
		rotatelogs.WithRotationCount(0),           // 不限制文件数量，由 MaxAge 控制
	)
	if err != nil {
		rx_r.Close()
		rx_w.Close()
		tx_r.Close()
		tx_w.Close()
		return nil, fmt.Errorf("failed to create plugin log rotator: %w", err)
	}

	// 6. 启动插件进程
	cmd := exec.CommandContext(ctx, execPath)
	cmd.Dir = workDir
	cmd.ExtraFiles = []*os.File{tx_r, rx_w} // 文件描述符 3 (tx_r), 4 (rx_w)
	cmd.Stdout = logWriter
	cmd.Stderr = logWriter
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // 创建新的进程组
	}

	// 设置环境变量（注入 PLUGIN_DIR 供插件查找内置二进制）
	rtInfo := agentrt.Get()
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PLUGIN_DIR=%s", workDir),
		fmt.Sprintf("MXCWPP_RUNTIME_TYPE=%s", rtInfo.Type),
		fmt.Sprintf("MXCWPP_IS_CONTAINER=%t", rtInfo.IsContainer),
		fmt.Sprintf("MXCWPP_CONTAINER_ID=%s", rtInfo.ContainerID),
	)

	if err := cmd.Start(); err != nil {
		logWriter.Close()
		rx_r.Close()
		rx_w.Close()
		tx_r.Close()
		tx_w.Close()
		return nil, fmt.Errorf("failed to start plugin: %w", err)
	}

	// 关闭子进程端不需要的文件描述符
	tx_r.Close()
	rx_w.Close()

	// 6.5 应用资源限制（prlimit）
	limits := parseResourceLimits(cfg.Detail)
	m.applyResourceLimits(cmd.Process.Pid, limits)

	// 7. 创建插件实例
	now := time.Now()
	plugin := &Plugin{
		Config:    cfg,
		cmd:       cmd,
		rx:        rx_r,
		tx:        tx_w,
		logWriter: logWriter,
		workDir:   workDir,
		status:    StatusStarting,
		startTime: now,
		lastPong:  now, // 初始化为启动时间，避免立即判定超时
		pingCh:    make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
		logger:    m.logger.With(zap.String("plugin", cfg.Name)),
	}

	// 8. 启动管理 goroutine
	go m.waitProcess(plugin)
	go m.receiveData(plugin)
	go m.sendTask(plugin)

	// 等待一小段时间，确认插件启动成功
	time.Sleep(100 * time.Millisecond)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		// 检查退出码：exit(10) = 依赖不可用，进入休眠而非报错
		exitCode := cmd.ProcessState.ExitCode()
		if exitCode == ExitCodeDepUnavailable {
			plugin.mu.Lock()
			plugin.status = StatusDormant
			plugin.dormantSince = time.Now()
			plugin.exitCode = exitCode
			plugin.mu.Unlock()
			plugin.logger.Warn("plugin dependency unavailable, entering dormant mode",
				zap.String("plugin", cfg.Name), zap.Int("exit_code", exitCode))
			return plugin, nil // 返回 plugin 以便存入 map，后续 watchPlugins 定期探测
		}
		return nil, fmt.Errorf("plugin exited immediately")
	}

	plugin.mu.Lock()
	plugin.status = StatusRunning
	plugin.mu.Unlock()

	plugin.logger.Info("plugin loaded successfully", zap.String("version", cfg.Version))

	// 9. 重新分发未完成的任务（如果有任务追踪器）
	if m.taskTracker != nil {
		go m.retryPendingTasks(plugin)
	}

	return plugin, nil
}

// validatePluginConfig 验证插件配置
func (m *Manager) validatePluginConfig(cfg *grpc.Config) error {
	if cfg.Name == "" {
		return fmt.Errorf("plugin name is required")
	}
	// 插件名会拼入落盘路径 filepath.Join(workDir, "plugins", cfg.Name)，
	// 必须是纯文件名，禁止路径分隔符/.. 防目录穿越（否则可在 agent 目录外写可执行文件 → RCE）。
	if strings.ContainsAny(cfg.Name, "/\\") || strings.Contains(cfg.Name, "..") {
		return fmt.Errorf("plugin name contains illegal path characters: %q", cfg.Name)
	}
	if cfg.Version == "" {
		return fmt.Errorf("plugin version is required")
	}
	if len(cfg.DownloadUrls) == 0 {
		return fmt.Errorf("plugin download URLs are required")
	}
	return nil
}

// downloadPlugin 下载插件并验证 SHA256
// 支持两种格式：单个二进制文件 或 tar.gz 包（通过文件头 magic bytes 自动识别）
func (m *Manager) downloadPlugin(cfg *grpc.Config, workDir string) (string, error) {
	execPath := filepath.Join(workDir, cfg.Name)

	// 检查插件是否已存在且 SHA256 匹配
	if info, err := os.Stat(execPath); err == nil {
		// 验证 SHA256
		if cfg.Sha256 != "" {
			actualSHA256, err := m.calculateSHA256(execPath)
			if err == nil && actualSHA256 == cfg.Sha256 {
				// SHA256 匹配，检查可执行权限
				if info.Mode().Perm()&0111 != 0 {
					m.logger.Debug("plugin already exists and SHA256 matches",
						zap.String("name", cfg.Name),
						zap.String("path", execPath),
						zap.String("sha256", cfg.Sha256))
					return execPath, nil
				}
				// SHA256 匹配但缺少可执行权限，设置权限
				if err := os.Chmod(execPath, 0755); err != nil {
					m.logger.Warn("failed to set executable permission", zap.Error(err))
				} else {
					return execPath, nil
				}
			} else if err == nil {
				// SHA256 不匹配，需要重新下载
				m.logger.Info("plugin SHA256 mismatch, re-downloading",
					zap.String("name", cfg.Name),
					zap.String("expected", cfg.Sha256),
					zap.String("actual", actualSHA256))
				// 删除旧文件
				if err := os.Remove(execPath); err != nil {
					m.logger.Warn("failed to remove old plugin", zap.Error(err))
				}
			}
		} else {
			// 没有 SHA256 配置，检查可执行权限
			if info.Mode().Perm()&0111 != 0 {
				m.logger.Debug("plugin already exists (no SHA256 check)",
					zap.String("name", cfg.Name),
					zap.String("path", execPath))
				return execPath, nil
			}
		}
	}

	// 下载插件
	if len(cfg.DownloadUrls) == 0 {
		return "", fmt.Errorf("no download URLs provided for plugin %s", cfg.Name)
	}

	// 尝试从每个 URL 下载
	var lastErr error
	for _, url := range cfg.DownloadUrls {
		m.logger.Info("downloading plugin",
			zap.String("name", cfg.Name),
			zap.String("url", url),
			zap.String("version", cfg.Version))

		// 下载到临时文件
		tmpPath := execPath + ".download"
		if err := m.downloadFromURL(url, tmpPath); err != nil {
			lastErr = err
			m.logger.Warn("failed to download from URL", zap.String("url", url), zap.Error(err))
			os.Remove(tmpPath)
			continue
		}

		// 检测文件格式：gzip magic bytes = 0x1f 0x8b
		isArchive, err := isGzipFile(tmpPath)
		if err != nil {
			lastErr = err
			os.Remove(tmpPath)
			continue
		}

		if isArchive {
			// tar.gz 格式：解压到工作目录
			m.logger.Info("detected tar.gz archive, extracting",
				zap.String("name", cfg.Name))
			os.Remove(tmpPath + ".sha256check")

			// 验证 SHA256（对 tar.gz 整体校验）
			if cfg.Sha256 != "" {
				actualSHA256, err := m.calculateSHA256(tmpPath)
				if err != nil {
					lastErr = fmt.Errorf("failed to calculate SHA256: %w", err)
					os.Remove(tmpPath)
					continue
				}
				if actualSHA256 != cfg.Sha256 {
					lastErr = fmt.Errorf("SHA256 mismatch: expected %s, got %s", cfg.Sha256, actualSHA256)
					m.logger.Error("SHA256 verification failed",
						zap.String("expected", cfg.Sha256),
						zap.String("actual", actualSHA256))
					os.Remove(tmpPath)
					continue
				}
				m.logger.Info("SHA256 verification passed", zap.String("sha256", cfg.Sha256))
			}

			// 签名验证
			if err := m.verifySignature(cfg.Sha256, cfg.Signature); err != nil {
				lastErr = err
				m.logger.Error("plugin signature verification failed",
					zap.String("name", cfg.Name), zap.Error(err))
				os.Remove(tmpPath)
				continue
			}

			// 解压
			if err := extractTarGz(tmpPath, workDir); err != nil {
				lastErr = fmt.Errorf("failed to extract tar.gz: %w", err)
				os.Remove(tmpPath)
				continue
			}
			os.Remove(tmpPath)

			// 设置可执行权限（数据类插件无可执行文件，跳过）
			if _, statErr := os.Stat(execPath); statErr != nil && os.IsNotExist(statErr) {
				// 数据类插件（如 virus-database）：tar.gz 只含数据文件，无同名可执行文件
				m.logger.Info("archive extracted (data-only plugin, no executable)",
					zap.String("name", cfg.Name),
					zap.String("work_dir", workDir))
				return workDir, nil
			}
			if err := os.Chmod(execPath, 0755); err != nil {
				lastErr = fmt.Errorf("failed to set executable permission: %w", err)
				continue
			}
		} else {
			// 单个二进制文件：直接移动
			// 验证 SHA256
			if cfg.Sha256 != "" {
				actualSHA256, err := m.calculateSHA256(tmpPath)
				if err != nil {
					lastErr = fmt.Errorf("failed to calculate SHA256: %w", err)
					os.Remove(tmpPath)
					continue
				}
				if actualSHA256 != cfg.Sha256 {
					lastErr = fmt.Errorf("SHA256 mismatch: expected %s, got %s", cfg.Sha256, actualSHA256)
					m.logger.Error("SHA256 verification failed",
						zap.String("expected", cfg.Sha256),
						zap.String("actual", actualSHA256))
					os.Remove(tmpPath)
					continue
				}
				m.logger.Info("SHA256 verification passed", zap.String("sha256", cfg.Sha256))
			}

			// 签名验证
			if err := m.verifySignature(cfg.Sha256, cfg.Signature); err != nil {
				lastErr = err
				m.logger.Error("plugin signature verification failed",
					zap.String("name", cfg.Name), zap.Error(err))
				os.Remove(tmpPath)
				continue
			}

			// 移动到最终路径
			if err := os.Rename(tmpPath, execPath); err != nil {
				lastErr = fmt.Errorf("failed to rename plugin: %w", err)
				os.Remove(tmpPath)
				continue
			}

			// 设置可执行权限
			if err := os.Chmod(execPath, 0755); err != nil {
				lastErr = fmt.Errorf("failed to set executable permission: %w", err)
				os.Remove(execPath)
				continue
			}
		}

		m.logger.Info("plugin downloaded successfully",
			zap.String("name", cfg.Name),
			zap.String("path", execPath),
			zap.Bool("archive", isArchive))
		return execPath, nil
	}

	return "", fmt.Errorf("failed to download plugin from all URLs: %w", lastErr)
}

// isGzipFile 检测文件是否为 gzip 格式（通过 magic bytes 0x1f 0x8b）
func isGzipFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	magic := make([]byte, 2)
	n, err := f.Read(magic)
	if err != nil || n < 2 {
		return false, nil
	}
	return magic[0] == 0x1f && magic[1] == 0x8b, nil
}

// extractTarGz 解压 tar.gz 到目标目录
func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}

		// 安全检查：防止路径穿越
		target := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)) {
			return fmt.Errorf("tar entry attempts path traversal: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}

// downloadFromURL 从 URL 下载文件（支持 http://, https://, file:// 协议）
func (m *Manager) downloadFromURL(urlStr, destPath string) error {
	// 支持 file:// 协议（本地文件复制）
	if strings.HasPrefix(urlStr, "file://") {
		srcPath := strings.TrimPrefix(urlStr, "file://")
		return m.copyFile(srcPath, destPath)
	}

	// HTTP/HTTPS 下载（支持 429 限流和瞬时错误重试）
	client := &http.Client{
		Timeout: 10 * time.Minute,
	}

	const maxRetries = 5
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(5<<(attempt-1)) * time.Second
			m.logger.Info("retrying download after backoff",
				zap.String("url", urlStr),
				zap.Duration("backoff", backoff),
				zap.Int("attempt", attempt+1),
				zap.Error(lastErr))
			time.Sleep(backoff)
		}

		err := m.doDownload(client, urlStr, destPath)
		if err == nil {
			return nil
		}
		lastErr = err

		// 判断是否可重试：EOF / connection reset / timeout 类瞬时错误
		if !isRetryableError(err) {
			return err
		}
	}
	return lastErr
}

// doDownload 执行单次 HTTP 下载
func (m *Manager) doDownload(client *http.Client, urlStr, destPath string) error {
	resp, err := client.Get(urlStr)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("server rate limit (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return &nonRetryableError{fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
	}

	// 创建目标文件
	destFile, err := os.Create(destPath)
	if err != nil {
		return &nonRetryableError{fmt.Errorf("failed to create file: %w", err)}
	}
	defer destFile.Close()

	// 限速下载（10 MB/s），避免多 Agent 同时下载占满带宽
	reader := newRateLimitedReader(resp.Body, 10*1024*1024)
	_, err = io.Copy(destFile, reader)
	if err != nil {
		os.Remove(destPath)
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// nonRetryableError 标记不应重试的错误
type nonRetryableError struct{ error }

func (e *nonRetryableError) Unwrap() error { return e.error }

// isRetryableError 判断是否为可重试的瞬时错误
func isRetryableError(err error) bool {
	if _, ok := err.(*nonRetryableError); ok {
		return false
	}
	return true
}

// copyFile 复制文件（用于 file:// 协议）
func (m *Manager) copyFile(srcPath, destPath string) error {
	// 打开源文件
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", srcPath, err)
	}
	defer srcFile.Close()

	// 获取源文件信息
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	// 创建目标文件
	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create dest file: %w", err)
	}
	defer destFile.Close()

	// 复制内容
	if _, err := io.Copy(destFile, srcFile); err != nil {
		os.Remove(destPath)
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// 设置可执行权限
	if err := os.Chmod(destPath, srcInfo.Mode()|0111); err != nil {
		m.logger.Warn("failed to set executable permission", zap.String("path", destPath), zap.Error(err))
	}

	m.logger.Info("copied plugin from local path",
		zap.String("src", srcPath),
		zap.String("dest", destPath),
		zap.String("size", fmt.Sprintf("%d bytes", srcInfo.Size())))

	return nil
}

// verifySignature 验证插件签名
func (m *Manager) verifySignature(sha256Hex, signature string) error {
	// 公钥未配置 → 未启用签名验证，跳过
	if m.cfg.SignPublicKey == "" {
		m.logger.Warn("sign public key not configured, skipping signature verification")
		return nil
	}
	// 公钥已配置但签名为空 → 拒绝加载（防止绕过签名验证）
	if signature == "" {
		return fmt.Errorf("plugin signature is empty but sign public key is configured, refusing to load unsigned plugin")
	}

	if err := signing.VerifySHA256(m.cfg.SignPublicKey, sha256Hex, signature); err != nil {
		return fmt.Errorf("plugin signature verification failed: %w", err)
	}
	m.logger.Info("plugin signature verification passed", zap.String("sha256", sha256Hex))
	return nil
}

// backupPlugin 备份插件二进制文件（保留最近一个备份）
func (m *Manager) backupPlugin(name string) (string, error) {
	workDir := filepath.Join(m.cfg.GetWorkDir(), "plugins", name)
	execPath := filepath.Join(workDir, name)

	// 文件不存在，无需备份
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		return "", nil
	}

	backupDir := filepath.Join(workDir, "backup")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup dir: %w", err)
	}

	backupPath := filepath.Join(backupDir, name)
	if err := m.copyFile(execPath, backupPath); err != nil {
		return "", fmt.Errorf("failed to backup plugin: %w", err)
	}

	m.logger.Info("plugin binary backed up",
		zap.String("name", name),
		zap.String("backup_path", backupPath))
	return backupPath, nil
}

// restoreFromBackup 从备份恢复插件二进制
func (m *Manager) restoreFromBackup(name string) error {
	workDir := filepath.Join(m.cfg.GetWorkDir(), "plugins", name)
	backupPath := filepath.Join(workDir, "backup", name)
	execPath := filepath.Join(workDir, name)

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	if err := m.copyFile(backupPath, execPath); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	if err := os.Chmod(execPath, 0755); err != nil {
		return fmt.Errorf("failed to set executable permission: %w", err)
	}

	m.logger.Info("plugin restored from backup",
		zap.String("name", name),
		zap.String("backup_path", backupPath))
	return nil
}

// calculateSHA256 计算文件的 SHA256 校验和
func (m *Manager) calculateSHA256(filePath string) (string, error) {
	return fileutil.SHA256Sum(filePath)
}

// waitProcess 等待插件进程退出，根据退出码决定后续行为
func (m *Manager) waitProcess(plugin *Plugin) {
	err := plugin.cmd.Wait()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	plugin.mu.Lock()
	wasRunning := plugin.status == StatusRunning
	plugin.exitCode = exitCode
	if plugin.status == StatusStopping {
		plugin.status = StatusStopped
	} else if exitCode == ExitCodeDepUnavailable {
		plugin.status = StatusDormant
		plugin.dormantSince = time.Now()
	} else {
		plugin.status = StatusError
	}
	plugin.mu.Unlock()

	if err != nil {
		plugin.logger.Error("plugin process exited with error",
			zap.Error(err), zap.Int("exit_code", exitCode))
	} else {
		plugin.logger.Info("plugin process exited", zap.Int("exit_code", exitCode))
	}

	plugin.rx.Close()
	plugin.tx.Close()
	if plugin.logWriter != nil {
		plugin.logWriter.Close()
	}
	close(plugin.stopCh)

	switch {
	case !wasRunning:
		// 非 Running 状态退出，不重启
	case exitCode == ExitCodeDepUnavailable:
		plugin.logger.Warn("plugin dependency unavailable, entering dormant mode",
			zap.String("plugin", plugin.Config.Name))
	case err != nil:
		plugin.logger.Warn("plugin crashed, will restart with backoff",
			zap.String("plugin", plugin.Config.Name), zap.Int("exit_code", exitCode))
		go m.restartPluginWithBackoff(plugin)
	default:
		// exit(0) 但非主动停止
		plugin.logger.Warn("plugin exited unexpectedly (code 0), will restart",
			zap.String("plugin", plugin.Config.Name))
		go m.restartPluginWithBackoff(plugin)
	}
}

// 退避重启常量
const (
	maxRestartCount  = 5
	baseRestartDelay = 3 * time.Second
	maxRestartDelay  = 5 * time.Minute
)

// restartPluginWithBackoff 退避重启崩溃的插件
func (m *Manager) restartPluginWithBackoff(oldPlugin *Plugin) {
	oldPlugin.mu.RLock()
	count := oldPlugin.restartCount
	oldPlugin.mu.RUnlock()

	if count >= maxRestartCount {
		oldPlugin.logger.Warn("restart count exceeded, entering dormant mode",
			zap.String("plugin", oldPlugin.Config.Name),
			zap.Int("restart_count", count))
		oldPlugin.mu.Lock()
		oldPlugin.status = StatusDormant
		oldPlugin.dormantSince = time.Now()
		oldPlugin.mu.Unlock()
		return
	}

	// 计算退避延迟：baseRestartDelay × 2^count
	delay := baseRestartDelay
	for i := 0; i < count; i++ {
		delay *= 2
		if delay > maxRestartDelay {
			delay = maxRestartDelay
			break
		}
	}

	oldPlugin.logger.Info("waiting before restart",
		zap.String("plugin", oldPlugin.Config.Name),
		zap.Duration("delay", delay),
		zap.Int("restart_count", count+1))
	time.Sleep(delay)

	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查插件是否还在管理列表中
	currentPlugin, exists := m.plugins[oldPlugin.Config.Name]
	if !exists || currentPlugin != oldPlugin {
		m.logger.Info("plugin already removed or replaced, skip restart",
			zap.String("plugin", oldPlugin.Config.Name))
		return
	}

	newPlugin, err := m.loadPlugin(m.ctx, oldPlugin.Config)
	if err != nil {
		m.logger.Error("failed to restart plugin with backoff",
			zap.String("plugin", oldPlugin.Config.Name),
			zap.Error(err))
		oldPlugin.mu.Lock()
		oldPlugin.restartCount = count + 1
		oldPlugin.mu.Unlock()
		// 超限则进入 dormant
		if count+1 >= maxRestartCount {
			oldPlugin.mu.Lock()
			oldPlugin.status = StatusDormant
			oldPlugin.dormantSince = time.Now()
			oldPlugin.mu.Unlock()
			m.logger.Warn("restart count exceeded after failure, entering dormant mode",
				zap.String("plugin", oldPlugin.Config.Name))
		}
		return
	}

	// 继承重启计数
	newPlugin.mu.Lock()
	newPlugin.restartCount = count + 1
	newPlugin.mu.Unlock()

	m.plugins[oldPlugin.Config.Name] = newPlugin
	m.logger.Info("plugin restarted successfully with backoff",
		zap.String("plugin", oldPlugin.Config.Name),
		zap.Int("restart_count", count+1))
}

// restartPlugin 重启崩溃的插件
func (m *Manager) restartPlugin(oldPlugin *Plugin) {
	// 等待一小段时间，避免快速重启循环
	time.Sleep(3 * time.Second)

	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查插件是否还在管理列表中
	currentPlugin, exists := m.plugins[oldPlugin.Config.Name]
	if !exists || currentPlugin != oldPlugin {
		m.logger.Info("plugin already removed or replaced, skip restart",
			zap.String("plugin", oldPlugin.Config.Name))
		return
	}

	m.logger.Info("restarting crashed plugin",
		zap.String("plugin", oldPlugin.Config.Name),
		zap.String("version", oldPlugin.Config.Version))

	// 重新加载插件
	newPlugin, err := m.loadPlugin(m.ctx, oldPlugin.Config)
	if err != nil {
		m.logger.Error("failed to restart plugin",
			zap.String("plugin", oldPlugin.Config.Name),
			zap.Error(err))
		return
	}

	// 替换插件实例
	m.plugins[oldPlugin.Config.Name] = newPlugin
	m.logger.Info("plugin restarted successfully",
		zap.String("plugin", oldPlugin.Config.Name))
}

// watchPlugins 定期检查插件健康状态
// 检查策略：
// 1. 进程是否还存活（发送 signal 0 检测）
// 2. 发送 IPC ping，检查插件是否在 pongTimeout 内回复 pong（精准假死检测）
// 所有插件统一心跳检测，不再区分任务驱动型/持续采集型
func (m *Manager) watchPlugins() {
	const checkInterval = 60 * time.Second // 每 60 秒检查一次
	const pongTimeout = 3 * time.Minute    // 容忍 3 次 ping 未回复

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.RLock()
			for name, plugin := range m.plugins {
				plugin.mu.RLock()
				status := plugin.status
				lastPong := plugin.lastPong
				plugin.mu.RUnlock()

				// 休眠插件：定期探测（1 小时间隔）
				if status == StatusDormant {
					const dormantRetryInterval = 1 * time.Hour
					plugin.mu.RLock()
					ds := plugin.dormantSince
					plugin.mu.RUnlock()
					if time.Since(ds) >= dormantRetryInterval {
						m.logger.Info("attempting to wake dormant plugin", zap.String("plugin", name))
						go m.wakeDormantPlugin(name)
					}
					continue
				}

				if status != StatusRunning {
					continue
				}

				// 运行稳定超过 10 分钟，重置重启计数
				plugin.mu.RLock()
				rc := plugin.restartCount
				plugin.mu.RUnlock()
				if rc > 0 && time.Since(plugin.startTime) > 10*time.Minute {
					plugin.mu.Lock()
					plugin.restartCount = 0
					plugin.mu.Unlock()
				}

				// 数据类插件（无进程）：跳过心跳检查
				if plugin.cmd == nil {
					continue
				}

				// 检查进程是否还存活（signal 0 不会杀进程，只检测是否存在）
				if plugin.cmd.Process != nil {
					if err := plugin.cmd.Process.Signal(syscall.Signal(0)); err != nil {
						m.logger.Warn("plugin process not alive, will be cleaned up by waitProcess",
							zap.String("plugin", name),
							zap.Error(err),
						)
						continue
					}
				}

				// 发送 ping（非阻塞写入 pingCh，最多缓存 1 次）
				select {
				case plugin.pingCh <- struct{}{}:
				default:
					// pingCh 已满，说明上次 ping 还没被 sendTask 消费，跳过
				}

				// 检查 pong 超时
				if time.Since(lastPong) > pongTimeout {
					m.logger.Warn("plugin heartbeat pong timeout, force restarting",
						zap.String("plugin", name),
						zap.Duration("since_last_pong", time.Since(lastPong)),
						zap.Time("last_pong", lastPong),
					)
					go m.forceRestartPlugin(name)
				}
			}
			m.mu.RUnlock()
		}
	}
}

// wakeDormantPlugin 尝试唤醒休眠的插件
func (m *Manager) wakeDormantPlugin(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldPlugin, exists := m.plugins[name]
	if !exists {
		return
	}
	oldPlugin.mu.RLock()
	isDormant := oldPlugin.status == StatusDormant
	oldPlugin.mu.RUnlock()
	if !isDormant {
		return
	}

	m.logger.Info("waking dormant plugin", zap.String("plugin", name))
	newPlugin, err := m.loadPlugin(m.ctx, oldPlugin.Config)
	if err != nil {
		m.logger.Warn("failed to wake dormant plugin",
			zap.String("plugin", name), zap.Error(err))
		oldPlugin.mu.Lock()
		oldPlugin.dormantSince = time.Now() // 重置计时器
		oldPlugin.mu.Unlock()
		return
	}
	m.plugins[name] = newPlugin
	m.logger.Info("dormant plugin woke up", zap.String("plugin", name))
}

// forceRestartPlugin 强制重启指定插件
func (m *Manager) forceRestartPlugin(name string) {
	m.mu.RLock()
	plugin, exists := m.plugins[name]
	m.mu.RUnlock()

	if !exists {
		return
	}

	// 先停止（等待 waitProcess 完成全部清理）
	_ = m.stopPlugin(plugin)

	// 显式确保任务通道已清理（防止旧 sendTask defer 延迟执行的竞争）
	m.transport.UnregisterTaskChannel(name)

	// 重启（不再需要 sleep，stopPlugin 已等待完整清理）
	m.restartPlugin(plugin)
}

// isCompletionSignal 判断 DataType 是否为任务完成信号
func isCompletionSignal(dataType int32) bool {
	switch dataType {
	case 8001, 8004: // baseline 完成/失败
		return true
	case 6002: // FIM 任务完成
		return true
	case 7002: // Scanner 扫描完成
		return true
	case 9200: // Remediation 修复结果
		return true
	default:
		return false
	}
}

// receiveData 接收插件数据（从 Pipe 读取）
func (m *Manager) receiveData(plugin *Plugin) {
	reader := bufio.NewReader(plugin.rx)

	for {
		select {
		case <-plugin.stopCh:
			return
		case <-m.ctx.Done():
			return
		default:
			// 读取长度（4 字节，小端序）
			var len uint32
			if err := binary.Read(reader, binary.LittleEndian, &len); err != nil {
				if err == io.EOF {
					return
				}
				plugin.logger.Error("failed to read record size", zap.Error(err))
				time.Sleep(time.Second)
				continue
			}

			// 限制最大消息大小
			const maxMessageSize = 10 * 1024 * 1024 // 10MB
			if len > maxMessageSize {
				plugin.logger.Error("record size exceeds maximum", zap.Uint32("size", len))
				// 跳过这个记录
				_, _ = io.CopyN(io.Discard, reader, int64(len))
				continue
			}

			// 读取数据
			buf := make([]byte, len)
			if _, err := io.ReadFull(reader, buf); err != nil {
				plugin.logger.Error("failed to read record data", zap.Error(err))
				continue
			}

			// 解析 Record（Agent 不解析，直接透传到 Server）
			record := &bridge.Record{}
			if err := proto.Unmarshal(buf, record); err != nil {
				plugin.logger.Error("failed to unmarshal record", zap.Error(err))
				continue
			}

			// 心跳 pong —— 更新时间戳，不透传到 server
			if record.DataType == DataTypeHeartbeatPong {
				plugin.mu.Lock()
				plugin.lastPong = time.Now()
				plugin.mu.Unlock()
				continue
			}

			// 检查是否是任务完成信号
			// 8001/8004=基线, 6002=FIM, 7002=Scanner, 9200=Remediation
			if m.taskTracker != nil && isCompletionSignal(record.DataType) {
				// 从 payload 中提取 task_id
				if record.Data != nil && record.Data.Fields != nil {
					if taskID, ok := record.Data.Fields["task_id"]; ok && taskID != "" {
						// 标记任务完成
						if err := m.taskTracker.MarkCompleted(taskID); err != nil {
							plugin.logger.Warn("failed to mark task as completed",
								zap.String("task_id", taskID),
								zap.Error(err))
						}
					}
				}
			}

			// 透传到 Server（通过 transport 模块）
			if err := m.transport.SendPluginData(plugin.Config.Name, record); err != nil {
				plugin.logger.Error("failed to send plugin data to server", zap.Error(err))
			}
		}
	}
}

// sendTask 发送任务到插件（写入 Pipe）
func (m *Manager) sendTask(plugin *Plugin) {
	writer := bufio.NewWriter(plugin.tx)
	defer writer.Flush()

	// 为该插件注册专用任务通道（按插件名称分发）
	taskCh := m.transport.RegisterTaskChannel(plugin.Config.Name)
	if taskCh == nil {
		plugin.logger.Warn("failed to register task channel")
		return
	}
	// 插件停止时注销任务通道
	defer m.transport.UnregisterTaskChannel(plugin.Config.Name)

	plugin.logger.Debug("task channel registered for plugin",
		zap.String("plugin_name", plugin.Config.Name))

	for {
		select {
		case <-plugin.stopCh:
			return
		case <-m.ctx.Done():
			return
		case <-plugin.pingCh:
			// 发送心跳 ping 到插件（轻量 Task，无 token，不经过 taskTracker）
			pingTask := &bridge.Task{DataType: DataTypeHeartbeatPing}
			pingData, err := proto.Marshal(pingTask)
			if err != nil {
				plugin.logger.Error("failed to marshal ping task", zap.Error(err))
				continue
			}
			pingLen := uint32(len(pingData))
			if err := binary.Write(writer, binary.LittleEndian, pingLen); err != nil {
				plugin.logger.Error("failed to write ping size", zap.Error(err))
				continue
			}
			if _, err := writer.Write(pingData); err != nil {
				plugin.logger.Error("failed to write ping data", zap.Error(err))
				continue
			}
			if err := writer.Flush(); err != nil {
				plugin.logger.Error("failed to flush ping data", zap.Error(err))
				continue
			}
		case task, ok := <-taskCh:
			if !ok {
				// 通道已关闭
				return
			}

			// 追踪任务（如果有任务追踪器）
			if m.taskTracker != nil {
				if err := m.taskTracker.TrackTask(task, plugin.Config.Name); err != nil {
					plugin.logger.Error("failed to track task", zap.Error(err))
				}
			}

			// 序列化任务为 bridge.Task
			bridgeTask := &bridge.Task{
				DataType:   task.DataType,
				ObjectName: task.ObjectName,
				Data:       task.Data,
				Token:      task.Token,
			}

			// 序列化为 protobuf
			taskData, err := proto.Marshal(bridgeTask)
			if err != nil {
				plugin.logger.Error("failed to marshal task", zap.Error(err))
				if m.taskTracker != nil {
					_ = m.taskTracker.MarkFailed(task.Token)
				}
				continue
			}

			// 写入长度（4 字节，小端序）
			len := uint32(len(taskData))
			if err := binary.Write(writer, binary.LittleEndian, len); err != nil {
				plugin.logger.Error("failed to write task size", zap.Error(err))
				if m.taskTracker != nil {
					_ = m.taskTracker.MarkFailed(task.Token)
				}
				continue
			}

			// 写入数据
			if _, err := writer.Write(taskData); err != nil {
				plugin.logger.Error("failed to write task data", zap.Error(err))
				if m.taskTracker != nil {
					_ = m.taskTracker.MarkFailed(task.Token)
				}
				continue
			}

			// 刷新缓冲区
			if err := writer.Flush(); err != nil {
				plugin.logger.Error("failed to flush task data", zap.Error(err))
				if m.taskTracker != nil {
					_ = m.taskTracker.MarkFailed(task.Token)
				}
				continue
			}

			// 标记任务已分发
			if m.taskTracker != nil {
				if err := m.taskTracker.MarkDispatched(task.Token); err != nil {
					plugin.logger.Warn("failed to mark task as dispatched", zap.Error(err))
				}
			}

			// Debug level: cron task 高频(每条都打 Info 会导致 journald rate-limit
			// 抑制后续所有日志,看起来像 agent hang 但实际只是日志被丢)
			plugin.logger.Debug("task sent to plugin",
				zap.String("task_token", task.Token),
				zap.Int32("data_type", task.DataType))
		}
	}
}

// stopPlugin 停止插件
// 注意：不直接调用 cmd.Wait()，而是等待 waitProcess 通过 stopCh 通知完成，
// 避免与 waitProcess 的 Wait() 调用产生竞争。
func (m *Manager) stopPlugin(plugin *Plugin) error {
	plugin.mu.Lock()
	if plugin.status != StatusRunning && plugin.status != StatusStarting {
		plugin.mu.Unlock()
		return nil
	}
	plugin.status = StatusStopping
	plugin.mu.Unlock()

	plugin.logger.Info("stopping plugin")

	// 数据类插件（无进程）：直接标记停止
	if plugin.cmd == nil {
		plugin.mu.Lock()
		plugin.status = StatusStopped
		plugin.mu.Unlock()
		plugin.logger.Info("plugin stopped")
		return nil
	}

	// 发送 SIGTERM 信号
	if plugin.cmd.Process != nil {
		if err := plugin.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			plugin.logger.Warn("failed to send SIGTERM", zap.Error(err))
		}
	}

	// 等待 waitProcess 完成清理（通过 stopCh 通知）
	select {
	case <-plugin.stopCh:
		plugin.logger.Info("plugin stopped")
	case <-time.After(5 * time.Second):
		plugin.logger.Warn("plugin did not stop gracefully, killing")
		if plugin.cmd.Process != nil {
			_ = plugin.cmd.Process.Kill()
		}
		// Kill 后再等 waitProcess 完成
		select {
		case <-plugin.stopCh:
			plugin.logger.Info("plugin stopped after kill")
		case <-time.After(3 * time.Second):
			plugin.logger.Error("plugin failed to stop even after kill")
		}
	}

	return nil
}

// ShutdownAll 关闭所有插件
func (m *Manager) ShutdownAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cancel()

	for name, plugin := range m.plugins {
		m.logger.Info("shutting down plugin", zap.String("name", name))
		if err := m.stopPlugin(plugin); err != nil {
			m.logger.Error("failed to stop plugin", zap.String("name", name), zap.Error(err))
		}
	}

	m.plugins = make(map[string]*Plugin)
}

// GetPluginStatus 获取插件状态
func (m *Manager) GetPluginStatus(name string) (Status, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, exists := m.plugins[name]
	if !exists {
		return StatusStopped, fmt.Errorf("plugin not found: %s", name)
	}

	plugin.mu.RLock()
	defer plugin.mu.RUnlock()

	return plugin.status, nil
}

// GetAllPluginStats 获取所有插件状态（用于心跳上报）
// 包含进程资源指标（CPU/RSS/FD），借鉴 Elkeid DataType=1001 的设计
func (m *Manager) GetAllPluginStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]interface{})
	for name, plugin := range m.plugins {
		plugin.mu.RLock()
		stat := map[string]interface{}{
			"status":        string(plugin.status),
			"version":       plugin.Config.Version,
			"start_time":    plugin.startTime.Unix(),
			"restart_count": plugin.restartCount,
			"exit_code":     plugin.exitCode,
		}
		if plugin.status == StatusDormant {
			stat["dormant_since"] = plugin.dormantSince.Unix()
		}

		// 采集运行中插件的进程资源指标
		if plugin.status == StatusRunning && plugin.cmd != nil && plugin.cmd.Process != nil {
			pid := plugin.cmd.Process.Pid
			stat["pid"] = pid
			if rss, err := getProcessRSS(pid); err == nil {
				stat["rss"] = rss // 内存占用（字节）
			}
			if nfd, err := getProcessFDCount(pid); err == nil {
				stat["nfd"] = nfd // 文件描述符数量
			}
		}

		plugin.mu.RUnlock()
		stats[name] = stat
	}

	return stats
}

// getProcessRSS 从 /proc/[pid]/statm 读取进程 RSS（单位：字节）
func getProcessRSS(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, err
	}
	var size, resident uint64
	_, err = fmt.Sscanf(string(data), "%d %d", &size, &resident)
	if err != nil {
		return 0, err
	}
	return resident * uint64(os.Getpagesize()), nil
}

// getProcessFDCount 读取进程打开的文件描述符数量
func getProcessFDCount(pid int) (int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// retryPendingTasks 重新分发未完成的任务
func (m *Manager) retryPendingTasks(plugin *Plugin) {
	// 等待插件完全启动
	time.Sleep(2 * time.Second)

	// 获取该插件的未完成任务
	pendingTasks := m.taskTracker.GetPendingTasks(plugin.Config.Name)
	if len(pendingTasks) == 0 {
		plugin.logger.Debug("no pending tasks to retry")
		return
	}

	plugin.logger.Info("retrying pending tasks",
		zap.String("plugin", plugin.Config.Name),
		zap.Int("count", len(pendingTasks)))

	// 重新分发任务
	for _, task := range pendingTasks {
		if err := m.transport.SendTaskToPlugin(plugin.Config.Name, task); err != nil {
			plugin.logger.Error("failed to re-dispatch pending task",
				zap.String("token", task.Token),
				zap.Error(err))
		} else {
			plugin.logger.Info("pending task re-dispatched",
				zap.String("token", task.Token),
				zap.Int32("data_type", task.DataType))
		}
	}
}

// taskCleanupLoop 定时清理超过 2 小时的僵尸任务
func (m *Manager) taskCleanupLoop() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.taskTracker.CleanupOldTasks(2 * time.Hour)
		}
	}
}

// rateLimitedReader 限速 Reader，用于控制下载速率
type rateLimitedReader struct {
	reader      io.Reader
	bytesPerSec int64
	lastTime    time.Time
	bytesRead   int64
}

func newRateLimitedReader(r io.Reader, bytesPerSec int64) *rateLimitedReader {
	return &rateLimitedReader{
		reader:      r,
		bytesPerSec: bytesPerSec,
		lastTime:    time.Now(),
	}
}

func (r *rateLimitedReader) Read(p []byte) (int, error) {
	// 检查是否需要限速
	elapsed := time.Since(r.lastTime)
	if elapsed > 0 && r.bytesRead > 0 {
		currentRate := float64(r.bytesRead) / elapsed.Seconds()
		if currentRate > float64(r.bytesPerSec) {
			// 计算需要等待的时间
			waitTime := time.Duration(float64(r.bytesRead)/float64(r.bytesPerSec)*float64(time.Second)) - elapsed
			if waitTime > 0 {
				time.Sleep(waitTime)
			}
		}
	}

	// 限制单次读取大小（64KB），细粒度控制速率
	maxRead := 64 * 1024
	if len(p) > maxRead {
		p = p[:maxRead]
	}

	n, err := r.reader.Read(p)
	r.bytesRead += int64(n)

	// 每秒重置计数器
	if elapsed >= time.Second {
		r.lastTime = time.Now()
		r.bytesRead = 0
	}

	return n, err
}
