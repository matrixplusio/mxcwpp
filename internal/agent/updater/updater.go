// Package updater 实现 Agent 自更新功能
package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/common/fileutil"
)

// --- 公共函数（供 gRPC push 和 CLI selfupdate 共用） ---

// DownloadFile 下载文件到指定路径
func DownloadFile(ctx context.Context, url string, destPath string) (int64, error) {
	client := &http.Client{
		Timeout: 10 * time.Minute,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to write file: %w", err)
	}

	return written, nil
}

// CalculateSHA256 计算文件的 SHA256 哈希值
func CalculateSHA256(filePath string) (string, error) {
	return fileutil.SHA256Sum(filePath)
}

// InstallPackage 使用系统包管理器安装包
func InstallPackage(pkgType string, pkgPath string) (string, error) {
	if _, err := os.Stat(pkgPath); err != nil {
		return "", fmt.Errorf("package file not accessible: %w", err)
	}

	// 检查 root 权限
	if os.Getuid() != 0 {
		return "", fmt.Errorf("root privileges required for package installation (current uid: %d)", os.Getuid())
	}

	var cmd *exec.Cmd
	switch pkgType {
	case "rpm":
		cmd = exec.Command("rpm", "-Uvh", "--force", pkgPath)
	case "deb":
		cmd = exec.Command("dpkg", "-i", pkgPath)
	default:
		return "", fmt.Errorf("unsupported package type: %s", pkgType)
	}

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		if strings.Contains(outputStr, "is already installed") {
			return outputStr, nil
		}
		return outputStr, fmt.Errorf("installation failed: %s, output: %s", err, outputStr)
	}

	return outputStr, nil
}

// RestartAgent 重启 Agent 服务（延迟执行，给调用方时间完成清理）
func RestartAgent() {
	go func() {
		time.Sleep(2 * time.Second)

		cmd := exec.Command("systemctl", "restart", "mxsec-agent")
		if err := cmd.Start(); err != nil {
			// systemctl 失败，直接退出让 systemd 自动重启
			os.Exit(0)
		}
	}()
}

// DetectPkgType 检测本机包管理器类型
func DetectPkgType() string {
	// 优先检查 rpm
	if _, err := exec.LookPath("rpm"); err == nil {
		return "rpm"
	}
	// 其次检查 dpkg
	if _, err := exec.LookPath("dpkg"); err == nil {
		return "deb"
	}
	return ""
}

// IsDowngrade 检查是否为版本降级
func IsDowngrade(currentVer, targetVer string) bool {
	currentVer = strings.TrimPrefix(currentVer, "v")
	targetVer = strings.TrimPrefix(targetVer, "v")

	currentParts := strings.Split(currentVer, ".")
	targetParts := strings.Split(targetVer, ".")

	maxLen := len(currentParts)
	if len(targetParts) > maxLen {
		maxLen = len(targetParts)
	}

	for i := 0; i < maxLen; i++ {
		var current, target int
		if i < len(currentParts) {
			fmt.Sscanf(currentParts[i], "%d", &current)
		}
		if i < len(targetParts) {
			fmt.Sscanf(targetParts[i], "%d", &target)
		}
		if target < current {
			return true
		} else if target > current {
			return false
		}
	}

	return false
}

// GetCurrentArch 获取当前系统架构
func GetCurrentArch() string {
	return runtime.GOARCH
}

// --- Manager: gRPC push 更新（原有逻辑，内部调用公共函数） ---

// Manager 是更新管理器（处理 Server 推送的更新命令）
type Manager struct {
	logger         *zap.Logger
	updateCh       <-chan *grpc.AgentUpdate
	currentVersion string
	workDir        string
	mu             sync.Mutex
	updating       bool
}

// NewManager 创建更新管理器
func NewManager(logger *zap.Logger, updateCh <-chan *grpc.AgentUpdate, currentVersion string, workDir string) *Manager {
	return &Manager{
		logger:         logger,
		updateCh:       updateCh,
		currentVersion: currentVersion,
		workDir:        workDir,
		updating:       false,
	}
}

// Startup 启动更新模块
func Startup(ctx context.Context, wg *sync.WaitGroup, logger *zap.Logger, updateCh <-chan *grpc.AgentUpdate, currentVersion string, workDir string) {
	mgr := NewManager(logger, updateCh, currentVersion, workDir)
	StartupWithManager(ctx, wg, mgr)
}

// StartupWithManager 使用已创建的管理器启动更新模块
func StartupWithManager(ctx context.Context, wg *sync.WaitGroup, mgr *Manager) {
	defer wg.Done()

	mgr.logger.Info("updater module started",
		zap.String("current_version", mgr.currentVersion),
		zap.String("work_dir", mgr.workDir),
	)

	for {
		select {
		case <-ctx.Done():
			mgr.logger.Info("updater module shutting down")
			return
		case update := <-mgr.updateCh:
			if update == nil {
				continue
			}
			mgr.handleUpdate(ctx, update)
		}
	}
}

// handleUpdate 处理更新命令
func (m *Manager) handleUpdate(ctx context.Context, update *grpc.AgentUpdate) {
	m.mu.Lock()
	if m.updating {
		m.mu.Unlock()
		m.logger.Warn("update already in progress, ignoring new update command")
		return
	}
	m.updating = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.updating = false
		m.mu.Unlock()
	}()

	m.logger.Info("processing agent update",
		zap.String("target_version", update.Version),
		zap.String("current_version", m.currentVersion),
		zap.String("download_url", update.DownloadUrl),
		zap.String("pkg_type", update.PkgType),
		zap.String("arch", update.Arch),
		zap.Bool("force", update.Force),
	)

	// 检查是否需要更新
	if !update.Force && update.Version == m.currentVersion {
		m.logger.Info("already running target version, skipping update",
			zap.String("version", update.Version),
		)
		return
	}

	// 检查是否为版本降级
	if IsDowngrade(m.currentVersion, update.Version) {
		m.logger.Warn("detected version downgrade (rollback)",
			zap.String("current_version", m.currentVersion),
			zap.String("target_version", update.Version),
			zap.Bool("force", update.Force),
		)
		if !update.Force {
			m.logger.Info("allowing downgrade without force flag")
		}
	}

	// 验证架构匹配
	currentArch := GetCurrentArch()
	if currentArch != update.Arch {
		m.logger.Error("architecture mismatch",
			zap.String("current_arch", currentArch),
			zap.String("update_arch", update.Arch),
		)
		return
	}

	// 验证包类型
	if update.PkgType != "rpm" && update.PkgType != "deb" {
		m.logger.Error("unsupported package type",
			zap.String("pkg_type", update.PkgType),
		)
		return
	}

	// 执行更新流程
	if err := m.doUpdate(ctx, update); err != nil {
		m.logger.Error("update failed",
			zap.String("version", update.Version),
			zap.Error(err),
		)
		return
	}

	m.logger.Info("update completed successfully, restarting agent",
		zap.String("version", update.Version),
	)

	// 重启 Agent
	m.logger.Info("restarting mxsec-agent service...")
	RestartAgent()
}

// doUpdate 执行更新流程（下载 → 校验 → 安装）
func (m *Manager) doUpdate(ctx context.Context, update *grpc.AgentUpdate) error {
	// 1. 创建临时目录
	tmpDir := filepath.Join(m.workDir, "update_tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// 2. 确定包文件名
	pkgFileName := fmt.Sprintf("mxsec-agent-%s.%s", update.Version, update.PkgType)
	pkgPath := filepath.Join(tmpDir, pkgFileName)

	// 3. 下载包文件
	m.logger.Info("downloading update package",
		zap.String("url", update.DownloadUrl),
		zap.String("dest", pkgPath),
	)

	written, err := DownloadFile(ctx, update.DownloadUrl, pkgPath)
	if err != nil {
		return fmt.Errorf("failed to download package: %w", err)
	}
	m.logger.Debug("file downloaded", zap.String("path", pkgPath), zap.Int64("bytes", written))

	// 4. 验证 SHA256
	m.logger.Info("verifying package checksum",
		zap.String("expected_sha256", update.Sha256),
	)

	actualSHA256, err := CalculateSHA256(pkgPath)
	if err != nil {
		return fmt.Errorf("failed to calculate SHA256: %w", err)
	}

	if !strings.EqualFold(actualSHA256, update.Sha256) {
		return fmt.Errorf("SHA256 mismatch: expected %s, got %s", update.Sha256, actualSHA256)
	}

	m.logger.Info("checksum verified successfully")

	// 5. 诊断系统环境
	m.diagnoseSystemEnv(update.PkgType)

	// 6. 安装包
	m.logger.Info("installing update package",
		zap.String("pkg_type", update.PkgType),
		zap.String("pkg_path", pkgPath),
	)

	output, err := InstallPackage(update.PkgType, pkgPath)
	m.logger.Info("package installation output",
		zap.String("output", output),
		zap.Bool("success", err == nil),
	)
	if err != nil {
		return err
	}

	m.logger.Info("package installed successfully")
	return nil
}

// diagnoseSystemEnv 诊断系统环境（仅日志记录，供 gRPC push 模式使用）
func (m *Manager) diagnoseSystemEnv(pkgType string) {
	uid := os.Getuid()
	gid := os.Getgid()

	m.logger.Info("system environment diagnostic",
		zap.Int("uid", uid),
		zap.Int("gid", gid),
		zap.Bool("is_root", uid == 0),
	)

	if uid != 0 {
		m.logger.Warn("agent is not running as root, package installation may fail",
			zap.Int("current_uid", uid),
			zap.String("hint", "ensure mxsec-agent.service has User=root in systemd config"),
		)
	}

	if pkgType == "rpm" {
		rpmDbPath := "/var/lib/rpm"
		if stat, err := os.Stat(rpmDbPath); err != nil {
			m.logger.Warn("rpm database directory not accessible",
				zap.String("path", rpmDbPath),
				zap.Error(err),
			)
		} else {
			m.logger.Debug("rpm database directory status",
				zap.String("path", rpmDbPath),
				zap.String("mode", stat.Mode().String()),
				zap.Bool("is_dir", stat.IsDir()),
			)
		}

		if tmpFile, err := os.CreateTemp(rpmDbPath, "test-write-*"); err != nil {
			m.logger.Error("rpm database directory is not writable",
				zap.String("path", rpmDbPath),
				zap.Error(err),
				zap.String("hint", "check filesystem mount options with 'mount | grep /var'"),
			)
		} else {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			m.logger.Debug("rpm database directory is writable")
		}
	}
}
