package engine

import (
	"context"

	"go.uber.org/zap"
)

// Engine 扫描引擎协调层，串联 ClamAV + YARA-X
type Engine struct {
	clamav     *ClamAVScanner
	yara       *YARAScanner
	quarantine *QuarantineManager
	logger     *zap.Logger
}

// NewEngine 创建扫描引擎
func NewEngine(logger *zap.Logger) *Engine {
	return &Engine{
		clamav:     NewClamAVScanner(logger),
		yara:       NewYARAScanner(logger),
		quarantine: NewQuarantineManager(logger),
		logger:     logger,
	}
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

	// 1. ClamAV 扫描
	clamResults, err := e.clamav.Scan(ctx, paths, DefaultExcludePaths)
	if err != nil {
		e.logger.Error("ClamAV 扫描失败", zap.Error(err))
	} else {
		allResults = append(allResults, clamResults...)
		e.logger.Info("ClamAV 扫描完成", zap.Int("threats", len(clamResults)))
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
