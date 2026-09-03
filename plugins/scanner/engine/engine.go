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

	// lastOutcome 最近一次扫描的整体结论，供上报层区分"扫过且干净"与"根本没扫"。
	lastOutcome ScanOutcome
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
	var reports []EngineReport

	// 1. ClamAV 扫描 (socket 优先, CLI 回退)
	if e.clamdSocket != nil && e.clamdSocket.Available() {
		sockResults := e.scanViaClamdSocket(ctx, paths)
		allResults = append(allResults, sockResults...)
		reports = append(reports, EngineReport{
			Engine: "clamav", Outcome: OutcomeScanned, Threats: len(sockResults)})
		e.logger.Info("clamd socket 扫描完成",
			zap.Int("threats", len(sockResults)),
			zap.Int("files", len(paths)))
	} else if !e.clamav.Available() {
		// 引擎不在就如实说不在。此前这里返回 (nil,nil)，与"扫过且干净"无法区分。
		reports = append(reports, EngineReport{
			Engine: "clamav", Outcome: OutcomeUnavailable, Reason: "clamscan 不可用"})
		e.logger.Warn("ClamAV 不可用，本次未执行 ClamAV 扫描")
	} else {
		clamResults, err := e.clamav.Scan(ctx, paths, DefaultExcludePaths)
		if err != nil {
			reports = append(reports, EngineReport{
				Engine: "clamav", Outcome: OutcomeFailed, Reason: err.Error()})
			e.logger.Error("ClamAV CLI 扫描失败", zap.Error(err))
		} else {
			allResults = append(allResults, clamResults...)
			reports = append(reports, EngineReport{
				Engine: "clamav", Outcome: OutcomeScanned, Threats: len(clamResults)})
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
	if !e.yara.Available() {
		reports = append(reports, EngineReport{
			Engine: "yara", Outcome: OutcomeUnavailable, Reason: "yara 引擎或规则不可用"})
		e.logger.Warn("YARA 不可用，本次未执行 YARA 扫描")
	} else if yaraResults, err := e.yara.Scan(ctx, paths); err != nil {
		reports = append(reports, EngineReport{
			Engine: "yara", Outcome: OutcomeFailed, Reason: err.Error()})
		e.logger.Error("YARA 扫描失败", zap.Error(err))
	} else {
		allResults = append(allResults, yaraResults...)
		reports = append(reports, EngineReport{
			Engine: "yara", Outcome: OutcomeScanned, Threats: len(yaraResults)})
		e.logger.Info("YARA 扫描完成", zap.Int("threats", len(yaraResults)))
	}

	// 去重：同一文件路径 + 同一引擎只保留一条
	allResults = dedup(allResults)

	e.lastOutcome = Summarize(reports, allResults)
	e.logger.Info("扫描完成",
		zap.String("task_id", req.TaskID),
		zap.String("status", e.lastOutcome.Status),
		zap.Int("total_threats", len(allResults)))
	if e.lastOutcome.Status != "clean" && e.lastOutcome.Status != "infected" {
		// 覆盖不全的结果不能被当成结论用，必须在日志里说清楚缺了什么。
		e.logger.Warn("扫描覆盖不完整，结果不足以判定主机干净",
			zap.String("task_id", req.TaskID),
			zap.String("status", e.lastOutcome.Status),
			zap.Any("engine_reports", reports))
	}

	return allResults, nil
}

// LastOutcome 返回最近一次扫描的整体结论，供上报层区分
// "扫过且干净" 与 "根本没扫"。
func (e *Engine) LastOutcome() ScanOutcome { return e.lastOutcome }

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
