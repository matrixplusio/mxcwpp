package engine

import (
	"context"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Engine 扫描引擎协调层，串联 ClamAV (socket 优先, CLI 回退) + YARA-X
type Engine struct {
	clamav      *ClamAVScanner
	clamdSocket *ClamdSocketScanner
	yara        *YARAScanner
	quarantine  *QuarantineManager
	logger      *zap.Logger
}

// NewEngine 创建扫描引擎
//
// 启动顺序:
//
//  1. 优先连 clamd UNIX socket (守护进程, 病毒库常驻内存, 10ms/file)
//  2. socket 不可用回退 clamscan CLI (每次启动加载 1GB DB, 5-15s/file)
//  3. 启动时跑 EICAR Selfcheck 验证通路
func NewEngine(logger *zap.Logger) *Engine {
	e := &Engine{
		clamav:      NewClamAVScanner(logger),
		clamdSocket: NewClamdSocketScanner("", logger),
		yara:        NewYARAScanner(logger),
		quarantine:  NewQuarantineManager(logger),
		logger:      logger,
	}
	// 启动期自检 (失败仅 warn, 不阻塞插件启动)
	go e.runStartupSelfcheck()
	return e
}

// runStartupSelfcheck 启动 5s 后跑一次 EICAR 自检。
func (e *Engine) runStartupSelfcheck() {
	if e.clamdSocket == nil || !e.clamdSocket.Available() {
		e.logger.Info("clamd socket 不可用, 跳过自检 (CLI 回退模式)")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.clamdSocket.Selfcheck(ctx); err != nil {
		e.logger.Warn("clamd EICAR 自检失败", zap.Error(err))
		return
	}
	ver, _ := e.clamdSocket.Version()
	e.logger.Info("clamd 自检通过", zap.String("version", strings.TrimSpace(ver)))
}

// Scan 执行扫描任务，串联 ClamAV + YARA-X，合并去重结果
func (e *Engine) Scan(ctx context.Context, req *ScanRequest) ([]ScanResult, error) {
	paths := req.Paths
	if len(paths) == 0 {
		switch req.ScanType {
		case "full":
			paths = DefaultFullPaths
		default: // quick, custom
			paths = DefaultQuickPaths
		}
	}

	e.logger.Info("开始扫描",
		zap.String("task_id", req.TaskID),
		zap.String("scan_type", req.ScanType),
		zap.Int("path_count", len(paths)))

	var allResults []ScanResult

	// 1. ClamAV 扫描 (socket 优先, CLI 回退)
	if e.clamdSocket != nil && e.clamdSocket.Available() {
		sockResults := e.scanViaClamdSocket(ctx, paths)
		allResults = append(allResults, sockResults...)
		e.logger.Info("clamd socket 扫描完成",
			zap.Int("threats", len(sockResults)),
			zap.Int("files", len(paths)))
	} else {
		clamResults, err := e.clamav.Scan(ctx, paths, DefaultExcludePaths)
		if err != nil {
			e.logger.Error("ClamAV CLI 扫描失败", zap.Error(err))
		} else {
			allResults = append(allResults, clamResults...)
			e.logger.Info("ClamAV CLI 扫描完成", zap.Int("threats", len(clamResults)))
		}
	}

	// 检查上下文
	select {
	case <-ctx.Done():
		return allResults, ctx.Err()
	default:
	}

	// 2. YARA-X 扫描
	yaraResults, err := e.yara.Scan(ctx, paths)
	if err != nil {
		e.logger.Error("YARA 扫描失败", zap.Error(err))
	} else {
		allResults = append(allResults, yaraResults...)
		e.logger.Info("YARA 扫描完成", zap.Int("threats", len(yaraResults)))
	}

	// 去重：同一文件路径 + 同一引擎只保留一条
	allResults = dedup(allResults)

	e.logger.Info("扫描完成",
		zap.String("task_id", req.TaskID),
		zap.Int("total_threats", len(allResults)))

	return allResults, nil
}

// HandleQuarantine 处理隔离/删除请求
func (e *Engine) HandleQuarantine(req *QuarantineRequest) (*QuarantineResult, error) {
	switch req.Action {
	case "quarantine":
		return e.quarantine.Quarantine(req.FilePath)
	case "delete":
		return e.quarantine.DeleteFile(req.FilePath)
	default:
		return &QuarantineResult{
			FilePath: req.FilePath,
			Action:   req.Action,
			Status:   "failed",
			ErrorMsg: "未知操作: " + req.Action,
		}, nil
	}
}

// scanViaClamdSocket 通过 socket 逐文件扫描 (整目录走 MULTISCAN, 后续优化)。
func (e *Engine) scanViaClamdSocket(ctx context.Context, paths []string) []ScanResult {
	var out []ScanResult
	for _, p := range paths {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		sig, err := e.clamdSocket.ScanFile(ctx, p)
		if err != nil {
			e.logger.Debug("clamd scan file 失败", zap.String("path", p), zap.Error(err))
			continue
		}
		if sig == "" {
			continue
		}
		out = append(out, ScanResult{
			FilePath:   p,
			ThreatName: sig,
			Engine:     "clamd_socket",
			Severity:   "high",
		})
	}
	return out
}

// dedup 对扫描结果按文件路径+引擎去重
func dedup(results []ScanResult) []ScanResult {
	seen := make(map[string]bool)
	var out []ScanResult

	for _, r := range results {
		key := r.FilePath + "|" + r.Engine + "|" + r.ThreatName
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}

	return out
}
