package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"go.uber.org/zap"
)

const quarantineDir = "/var/mxsec/quarantine"

// QuarantineManager 文件隔离管理器
type QuarantineManager struct {
	logger *zap.Logger
	dir    string
}

// NewQuarantineManager 创建隔离管理器
func NewQuarantineManager(logger *zap.Logger) *QuarantineManager {
	return &QuarantineManager{
		logger: logger,
		dir:    quarantineDir,
	}
}

// Quarantine 隔离文件：mv → /var/mxsec/quarantine/{sha256} + chmod 000
func (m *QuarantineManager) Quarantine(filePath string) (*QuarantineResult, error) {
	result := &QuarantineResult{
		FilePath: filePath,
		Action:   "quarantine",
	}

	// 获取文件信息
	info, err := os.Stat(filePath)
	if err != nil {
		result.Status = "failed"
		result.ErrorMsg = fmt.Sprintf("文件不存在: %v", err)
		return result, nil
	}

	// 记录原始权限和属主
	result.FilePermission = fmt.Sprintf("%o", info.Mode().Perm())
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		result.FileOwner = fmt.Sprintf("%d:%d", stat.Uid, stat.Gid)
	}

	// 计算文件哈希
	hash, _ := getFileInfo(filePath)
	if hash == "" {
		hash = filepath.Base(filePath)
	}

	// 确保隔离目录存在
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		result.Status = "failed"
		result.ErrorMsg = fmt.Sprintf("创建隔离目录失败: %v", err)
		return result, nil
	}

	// 目标路径
	destPath := filepath.Join(m.dir, hash)
	if _, err := os.Stat(destPath); err == nil {
		// 文件已存在，删除原文件
		if err := os.Remove(filePath); err != nil {
			result.Status = "failed"
			result.ErrorMsg = fmt.Sprintf("删除原文件失败: %v", err)
			return result, nil
		}
		result.Status = "success"
		result.QuarantinePath = destPath
		return result, nil
	}

	// 移动文件到隔离目录
	if err := os.Rename(filePath, destPath); err != nil {
		// 跨文件系统时 Rename 会失败，回退到 cp + rm
		if cpErr := copyAndRemove(filePath, destPath); cpErr != nil {
			result.Status = "failed"
			result.ErrorMsg = fmt.Sprintf("移动文件失败: %v", cpErr)
			return result, nil
		}
	}

	// 设置权限为 000（不可读写执行）
	if err := os.Chmod(destPath, 0000); err != nil {
		m.logger.Warn("设置隔离文件权限失败", zap.Error(err))
	}

	result.Status = "success"
	result.QuarantinePath = destPath

	m.logger.Info("文件已隔离",
		zap.String("file", filePath),
		zap.String("quarantine", destPath))

	return result, nil
}

// DeleteFile 删除恶意文件
func (m *QuarantineManager) DeleteFile(filePath string) (*QuarantineResult, error) {
	result := &QuarantineResult{
		FilePath: filePath,
		Action:   "delete",
	}

	if err := os.Remove(filePath); err != nil {
		result.Status = "failed"
		result.ErrorMsg = fmt.Sprintf("删除文件失败: %v", err)
		return result, nil
	}

	result.Status = "success"
	m.logger.Info("文件已删除", zap.String("file", filePath))
	return result, nil
}

// copyAndRemove 复制并删除文件（跨文件系统移动时使用）
func copyAndRemove(src, dst string) error {
	output, err := exec.Command("cp", "-a", src, dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cp 失败: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return os.Remove(src)
}
