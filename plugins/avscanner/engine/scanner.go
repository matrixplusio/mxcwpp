package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ScanRequest 是单次扫描请求 (Server → Agent → 本插件)。
type ScanRequest struct {
	TaskID    string
	Targets   []string // 文件/目录/通配
	MaxBytes  int64    // 单文件最大扫描字节数 (0 = 不限)
	HashOnly  bool     // 只算 hash, 不做 YARA 匹配 (Sprint 4 占位)
	FollowSym bool
}

// ScanFinding 是单条扫描结果。
type ScanFinding struct {
	Path     string
	SHA256   string
	Size     int64
	MIMEHint string
	Rule     string // YARA rule 命中名 (Sprint 5 接入)
	Severity string // info / low / medium / high / critical
	Detail   string
}

// ScanSummary 是扫描汇总。
type ScanSummary struct {
	TaskID      string
	StartedAt   time.Time
	FinishedAt  time.Time
	TotalFiles  int
	HitFindings int
	Errors      int
}

// Scanner 文件扫描引擎 (Sprint 4 仅 hash + 简单签名; Sprint 5 接入 ClamAV/YARA)。
type Scanner struct {
	logger *zap.Logger
	// 已知恶意 hash 列表 (后续 vulnsync 下发, 当前内嵌示例)
	knownBad map[string]string // sha256 → 描述
}

// NewScanner 构造。
func NewScanner(logger *zap.Logger) *Scanner {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scanner{
		logger: logger,
		knownBad: map[string]string{
			// EICAR 测试病毒 hash (用于自检)
			"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-AV-Test",
		},
	}
}

// Scan 执行一次扫描请求。
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) ([]ScanFinding, ScanSummary, error) {
	summary := ScanSummary{
		TaskID:    req.TaskID,
		StartedAt: time.Now(),
	}
	if len(req.Targets) == 0 {
		return nil, summary, errors.New("no scan targets")
	}
	var findings []ScanFinding
	for _, target := range req.Targets {
		// 提前 ctx 检查
		select {
		case <-ctx.Done():
			return findings, summary, ctx.Err()
		default:
		}
		err := s.walk(ctx, target, req, &findings, &summary)
		if err != nil {
			summary.Errors++
			s.logger.Warn("scan target failed", zap.String("target", target), zap.Error(err))
		}
	}
	summary.FinishedAt = time.Now()
	summary.HitFindings = len(findings)
	return findings, summary, nil
}

func (s *Scanner) walk(ctx context.Context, root string, req ScanRequest, findings *[]ScanFinding, summary *ScanSummary) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip 不可访问
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if info.IsDir() {
			if shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		summary.TotalFiles++
		f, e := s.scanFile(path, info, req)
		if e != nil {
			summary.Errors++
			return nil
		}
		if f != nil {
			*findings = append(*findings, *f)
		}
		return nil
	})
}

func (s *Scanner) scanFile(path string, info os.FileInfo, req ScanRequest) (*ScanFinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	var reader io.Reader = f
	if req.MaxBytes > 0 {
		reader = io.LimitReader(f, req.MaxBytes)
	}
	if _, err := io.Copy(h, reader); err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if desc, hit := s.knownBad[sum]; hit {
		return &ScanFinding{
			Path:     path,
			SHA256:   sum,
			Size:     info.Size(),
			Rule:     "known_bad_hash",
			Severity: "critical",
			Detail:   desc,
		}, nil
	}
	if req.HashOnly {
		return nil, nil
	}
	// Sprint 5 占位: 简单字符串签名
	if sig := quickSignature(path); sig != "" {
		return &ScanFinding{
			Path:     path,
			SHA256:   sum,
			Size:     info.Size(),
			Rule:     sig,
			Severity: "medium",
			Detail:   "quick signature hit",
		}, nil
	}
	return nil, nil
}

// shouldSkipDir 跳过系统/无关目录。
func shouldSkipDir(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "proc", "sys", "dev", ".git", "node_modules":
		return true
	}
	if strings.HasPrefix(path, "/proc/") || strings.HasPrefix(path, "/sys/") {
		return true
	}
	return false
}

// quickSignature 仅基于路径/扩展名的极快签名 (Sprint 4 占位)。
//
// Sprint 5: 替换为 YARA / ClamAV 引擎绑定。
func quickSignature(path string) string {
	low := strings.ToLower(path)
	switch {
	case strings.HasSuffix(low, ".jsp.png"),
		strings.HasSuffix(low, ".php.jpg"):
		return "suspicious_double_ext"
	case strings.Contains(low, "/tmp/.x") && strings.HasSuffix(low, ".elf"):
		return "tmp_hidden_elf"
	}
	return ""
}

// Selfcheck 写一份 EICAR 测试样本到 tmpDir, 扫一次,清理。
//
// Agent 启动可用此自检确认扫描通路。
func (s *Scanner) Selfcheck(ctx context.Context, tmpDir string) error {
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	eicar := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	path := filepath.Join(tmpDir, ".mxcwpp_av_selfcheck")
	if err := os.WriteFile(path, eicar, 0o600); err != nil {
		return fmt.Errorf("selfcheck write: %w", err)
	}
	defer os.Remove(path)
	findings, _, err := s.Scan(ctx, ScanRequest{
		TaskID: "selfcheck", Targets: []string{path},
	})
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return errors.New("selfcheck did not hit EICAR")
	}
	return nil
}
