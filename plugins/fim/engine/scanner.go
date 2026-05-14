package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"go.uber.org/zap"
)

const defaultWorkerCount = 4

// Scanner Go 原生文件扫描器
type Scanner struct {
	logger      *zap.Logger
	workerCount int
}

// NewScanner 创建扫描器实例
func NewScanner(logger *zap.Logger) *Scanner {
	return &Scanner{
		logger:      logger,
		workerCount: defaultWorkerCount,
	}
}

// ScanResult 扫描结果
type ScanResult struct {
	Entries map[string]FileEntry `json:"entries"`
	Errors  []string             `json:"errors,omitempty"`
}

// scanJob 扫描任务单元
type scanJob struct {
	path  string
	level string
}

// Scan 扫描策略中配置的所有监控路径，返回文件快照
func (s *Scanner) Scan(ctx context.Context, policy *FIMPolicy) (*ScanResult, error) {
	result := &ScanResult{
		Entries: make(map[string]FileEntry),
	}

	// 遍历所有监控路径，收集待扫描文件
	var jobs []scanJob
	for _, wp := range policy.WatchPaths {
		level := wp.Level
		if level == "" {
			level = "NORMAL"
		}
		err := filepath.WalkDir(wp.Path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("walk %s: %v", path, err))
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				if s.shouldExclude(path+"/", policy.ExcludePaths) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if s.shouldExclude(path, policy.ExcludePaths) {
				return nil
			}
			jobs = append(jobs, scanJob{path: path, level: level})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("遍历 %s 失败: %w", wp.Path, err)
		}
	}

	s.logger.Info("文件遍历完成，开始采集",
		zap.Int("file_count", len(jobs)))

	// 并发采集文件信息
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobCh := make(chan scanJob, len(jobs))

	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	for i := 0; i < s.workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				if ctx.Err() != nil {
					return
				}
				entry, err := s.collectEntry(job.path, job.level)
				if err != nil {
					mu.Lock()
					result.Errors = append(result.Errors, fmt.Sprintf("collect %s: %v", job.path, err))
					mu.Unlock()
					continue
				}
				mu.Lock()
				result.Entries[job.path] = entry
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	return result, nil
}

// collectEntry 采集单个文件的元数据和哈希
func (s *Scanner) collectEntry(path, level string) (FileEntry, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return FileEntry{}, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileEntry{}, fmt.Errorf("无法获取系统文件信息: %s", path)
	}

	entry := FileEntry{
		Size:  info.Size(),
		Mode:  info.Mode().String(),
		UID:   stat.Uid,
		GID:   stat.Gid,
		MTime: info.ModTime().Unix(),
	}

	// PERMS 级别仅采集权限信息，跳过哈希计算
	if strings.ToUpper(level) != "PERMS" {
		hash, err := s.hashFile(path)
		if err != nil {
			return FileEntry{}, fmt.Errorf("计算哈希失败: %w", err)
		}
		entry.SHA256 = hash
	}

	return entry, nil
}

// hashFile 计算文件的 SHA256 哈希
func (s *Scanner) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// shouldExclude 检查路径是否在排除列表中
func (s *Scanner) shouldExclude(path string, excludePaths []string) bool {
	for _, ep := range excludePaths {
		if strings.HasPrefix(path, ep) {
			return true
		}
		if matched, _ := filepath.Match(ep, path); matched {
			return true
		}
	}
	return false
}
