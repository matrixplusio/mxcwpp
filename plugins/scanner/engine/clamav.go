package engine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// clamscanMinAvailMemMB is the minimum available memory (MB) required to run
// clamscan. ClamAV loads the entire virus database into memory (~800MB-1GB).
// If the system has less available memory, the scan is skipped to prevent OOM.
const clamscanMinAvailMemMB = 1200

// ClamAVScanner 基于 clamscan CLI 的扫描器
type ClamAVScanner struct {
	logger *zap.Logger
}

// NewClamAVScanner 创建 ClamAV 扫描器
func NewClamAVScanner(logger *zap.Logger) *ClamAVScanner {
	return &ClamAVScanner{logger: logger}
}

// Available 检查 clamscan 是否可用（验证二进制可执行，非仅文件存在）
func (s *ClamAVScanner) Available() bool {
	bin := s.findBinary()
	if bin == "" {
		return false
	}
	// 验证二进制能实际运行（检测共享库依赖等问题）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	if err != nil {
		s.logger.Warn("clamscan 二进制存在但无法执行",
			zap.String("path", bin),
			zap.String("output", string(out)),
			zap.Error(err))
		return false
	}
	return true
}

// findBinary 查找 clamscan 路径：优先插件目录 → 系统 PATH
func (s *ClamAVScanner) findBinary() string {
	// 1. 插件工作目录下的 bin/clamscan
	if pluginDir := os.Getenv("PLUGIN_DIR"); pluginDir != "" {
		local := filepath.Join(pluginDir, "bin", "clamscan")
		if _, err := os.Stat(local); err == nil {
			return local
		}
	}
	// 2. 系统 PATH
	if p, err := exec.LookPath("clamscan"); err == nil {
		return p
	}
	return ""
}

// Scan 扫描指定路径，返回检测到的威胁列表
func (s *ClamAVScanner) Scan(ctx context.Context, paths []string, excludePaths []string) ([]ScanResult, error) {
	if !s.Available() {
		s.logger.Warn("clamscan 不可用，跳过 ClamAV 扫描")
		return nil, nil
	}

	// ClamAV loads the entire virus database into memory (~800MB-1GB).
	// Check available memory to prevent OOM killing the agent process.
	if avail := availableMemoryMB(); avail > 0 && avail < clamscanMinAvailMemMB {
		s.logger.Warn("可用内存不足，跳过 ClamAV 扫描以防止 OOM",
			zap.Int64("available_mb", avail),
			zap.Int64("required_mb", clamscanMinAvailMemMB))
		return nil, nil
	}

	var results []ScanResult

	for _, scanPath := range paths {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		pathResults, err := s.scanPath(ctx, scanPath, excludePaths)
		if err != nil {
			s.logger.Error("ClamAV 扫描路径失败",
				zap.String("path", scanPath),
				zap.Error(err))
			continue
		}
		results = append(results, pathResults...)
	}

	return results, nil
}

// findVirusDBDir 查找本地病毒库目录（由 virus-database 插件下发）
func (s *ClamAVScanner) findVirusDBDir() string {
	pluginDir := os.Getenv("PLUGIN_DIR")
	if pluginDir == "" {
		return ""
	}
	// virus-database 插件目录与 scanner 同级：$PLUGIN_DIR/../virus-database/
	dbDir := filepath.Join(pluginDir, "..", "virus-database")
	// 检查是否存在 .cvd 或 .cld 文件
	for _, pattern := range []string{"*.cvd", "*.cld"} {
		matches, _ := filepath.Glob(filepath.Join(dbDir, pattern))
		if len(matches) > 0 {
			return dbDir
		}
	}
	return ""
}

// scanPath 扫描单个路径
func (s *ClamAVScanner) scanPath(ctx context.Context, scanPath string, excludePaths []string) ([]ScanResult, error) {
	args := []string{
		"--recursive",
		"--infected",   // 只输出感染文件
		"--no-summary", // 不输出统计信息
		"--stdout",     // 输出到 stdout
		"--max-filesize=50M",
		"--max-scansize=200M",
	}

	// 检测本地病毒库目录（virus-database 插件下发），若存在则指定 --database
	if dbDir := s.findVirusDBDir(); dbDir != "" {
		args = append(args, fmt.Sprintf("--database=%s", dbDir))
		s.logger.Debug("使用本地病毒库", zap.String("db_dir", dbDir))
	}

	for _, exclude := range excludePaths {
		args = append(args, fmt.Sprintf("--exclude-dir=%s", exclude))
	}

	args = append(args, scanPath)

	clamscanBin := s.findBinary()
	cmd := exec.CommandContext(ctx, clamscanBin, args...)
	output, err := cmd.Output()

	// clamscan 返回码：0=无感染, 1=有感染, 2=错误
	// 有感染时 err != nil（exit code 1），但输出是有效的
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				// 发现感染文件，继续解析输出
			} else {
				return nil, fmt.Errorf("clamscan 执行错误 (exit %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
			}
		} else {
			return nil, fmt.Errorf("clamscan 执行失败: %w", err)
		}
	}

	return s.parseOutput(string(output))
}

// parseOutput 解析 clamscan 输出
// 格式: /path/to/file: ThreatName FOUND
func (s *ClamAVScanner) parseOutput(output string) ([]ScanResult, error) {
	var results []ScanResult

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasSuffix(line, "FOUND") {
			continue
		}

		// 解析格式: /path/to/file: ThreatName FOUND
		colonIdx := strings.LastIndex(line, ": ")
		if colonIdx < 0 {
			continue
		}

		filePath := line[:colonIdx]
		threatPart := strings.TrimSuffix(line[colonIdx+2:], " FOUND")
		threatPart = strings.TrimSpace(threatPart)

		if filePath == "" || threatPart == "" {
			continue
		}

		threatType := classifyThreat(threatPart)

		result := ScanResult{
			FilePath:   filePath,
			ThreatName: threatPart,
			ThreatType: threatType,
			Severity:   getSeverity(threatType),
			Engine:     "clamav",
			DetectedAt: time.Now(),
		}

		// 获取文件信息
		result.FileHash, result.FileSize = getFileInfo(filePath)

		results = append(results, result)
	}

	return results, nil
}

// availableMemoryMB returns the lesser of system MemAvailable and cgroup
// remaining memory (cgroup v2: memory.max - memory.current).
// If running under a cgroup with MemoryMax (e.g. systemd service), the cgroup
// limit is typically the binding constraint, not system-wide MemAvailable.
// Returns -1 if the value cannot be determined (non-Linux or read error).
func availableMemoryMB() int64 {
	sysAvail := sysMemAvailableMB()
	cgAvail := cgroupAvailableMB()

	switch {
	case sysAvail > 0 && cgAvail > 0:
		if cgAvail < sysAvail {
			return cgAvail
		}
		return sysAvail
	case cgAvail > 0:
		return cgAvail
	case sysAvail > 0:
		return sysAvail
	default:
		return -1
	}
}

// sysMemAvailableMB reads MemAvailable from /proc/meminfo.
func sysMemAvailableMB() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return -1
}

// cgroupAvailableMB returns (memory.max - memory.current) in MB for cgroup v2.
// Returns -1 if not running under cgroup v2 or values unreadable.
func cgroupAvailableMB() int64 {
	// Discover the cgroup directory once, then read both max and current from it.
	cgDir := discoverCgroupDir()
	if cgDir == "" {
		return -1
	}

	maxBytes, err := readCgroupValue(filepath.Join(cgDir, "memory.max"))
	if err != nil || maxBytes <= 0 {
		return -1 // "max" or unreadable means no limit
	}

	curBytes, err := readCgroupValue(filepath.Join(cgDir, "memory.current"))
	if err != nil || curBytes < 0 {
		curBytes = 0
	}

	avail := (maxBytes - curBytes) / (1024 * 1024)
	if avail < 0 {
		return 0
	}
	return avail
}

// discoverCgroupDir returns the cgroup v2 directory for this process.
// Tries /proc/self/cgroup to find the service-scoped path (e.g.
// /sys/fs/cgroup/system.slice/mxcwpp-agent.service).
func discoverCgroupDir() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		// cgroup v2 line: "0::/system.slice/mxcwpp-agent.service"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			dir := "/sys/fs/cgroup" + strings.TrimSpace(parts[2])
			if _, err := os.Stat(filepath.Join(dir, "memory.max")); err == nil {
				return dir
			}
		}
	}
	return ""
}

// readCgroupValue reads a single int64 value from a cgroup file.
// Returns -1 for "max" (no limit).
func readCgroupValue(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return -1, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// classifyThreat 根据 ClamAV 威胁名称分类
func classifyThreat(threatName string) string {
	lower := strings.ToLower(threatName)
	switch {
	case strings.Contains(lower, "trojan"):
		return "trojan"
	case strings.Contains(lower, "ransom"):
		return "ransomware"
	case strings.Contains(lower, "rootkit"):
		return "rootkit"
	case strings.Contains(lower, "backdoor"):
		return "backdoor"
	case strings.Contains(lower, "miner") || strings.Contains(lower, "coinminer"):
		return "miner"
	case strings.Contains(lower, "worm"):
		return "worm"
	case strings.Contains(lower, "virus"):
		return "virus"
	default:
		return "other"
	}
}

// getSeverity 获取威胁严重级别
func getSeverity(threatType string) string {
	if s, ok := ThreatSeverityMap[threatType]; ok {
		return s
	}
	return "medium"
}

// getFileInfo 获取文件的 SHA256 和大小（纯 Go 实现，跨平台）
func getFileInfo(filePath string) (string, int64) {
	info, err := os.Stat(filePath)
	if err != nil {
		return "", 0
	}
	size := info.Size()

	f, err := os.Open(filePath)
	if err != nil {
		return "", size
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", size
	}

	return hex.EncodeToString(h.Sum(nil)), size
}
