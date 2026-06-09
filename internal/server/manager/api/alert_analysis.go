package api

import (
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/llmproxy"
)

// AlertAnalysisHandler LLM 告警分析 API 处理器 (P1-10: 异步队列模式).
//
// 原 AnalyzeAlert 同步调 LLM 30s 阻塞 gin worker → 改为入队 + 轮询模式:
//  1. POST /analyze → 返 task_id, 后台 goroutine 跑 LLM
//  2. GET  /analyze/:task_id → 返结果或 pending 状态
//
// 任务结果存内存 cache, 上限 1000 条. 限并发 LLM 调用 4 个 (sem).
type AlertAnalysisHandler struct {
	db     *gorm.DB
	logger *zap.Logger
	cfg    *config.Config

	mu    sync.RWMutex
	tasks map[string]*analysisTask
	sem   chan struct{}
}

type analysisTask struct {
	ID        string    `json:"task_id"`
	AlertID   uint64    `json:"alert_id"`
	Status    string    `json:"status"`
	Result    any       `json:"result,omitempty"`
	Err       string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	DoneAt    time.Time `json:"done_at,omitempty"`
}

// NewAlertAnalysisHandler 创建告警分析处理器
func NewAlertAnalysisHandler(db *gorm.DB, logger *zap.Logger, cfg *config.Config) *AlertAnalysisHandler {
	return &AlertAnalysisHandler{
		db:     db,
		logger: logger,
		cfg:    cfg,
		tasks:  make(map[string]*analysisTask),
		sem:    make(chan struct{}, 4),
	}
}

// AnalyzeAlert P1-10: 入队 + 立刻返 task_id.
// POST /api/v1/alerts/:id/analyze
func (h *AlertAnalysisHandler) AnalyzeAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的告警 ID")
		return
	}

	llmCfg := h.cfg.LLM
	if llmCfg.APIURL == "" {
		BadRequest(c, "LLM 服务未配置")
		return
	}

	task := &analysisTask{
		ID:        uuid.NewString(),
		AlertID:   id,
		Status:    "pending",
		CreatedAt: time.Now(),
	}
	h.mu.Lock()
	if len(h.tasks) >= 1000 {
		var oldest string
		var oldestT time.Time
		for k, v := range h.tasks {
			if oldest == "" || v.CreatedAt.Before(oldestT) {
				oldest = k
				oldestT = v.CreatedAt
			}
		}
		delete(h.tasks, oldest)
	}
	h.tasks[task.ID] = task
	h.mu.Unlock()

	go h.runAnalysis(task, llmCfg.APIURL, llmCfg.APIKey, llmCfg.Model)

	Success(c, gin.H{
		"task_id": task.ID,
		"status":  "pending",
	})
}

// runAnalysis 后台跑 LLM, 写结果到 task.
func (h *AlertAnalysisHandler) runAnalysis(task *analysisTask, apiURL, apiKey, model string) {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	defer func() {
		if r := recover(); r != nil {
			h.mu.Lock()
			task.Status = "failed"
			task.Err = "panic recovered"
			h.mu.Unlock()
			h.logger.Error("LLM analyze panic recovered",
				zap.String("task_id", task.ID),
				zap.Any("panic", r))
		}
	}()
	assist := llmproxy.NewLLMAssist(h.db, h.logger, apiURL, apiKey, model)
	result, err := assist.AnalyzeAlert(uint(task.AlertID))
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		task.Status = "failed"
		task.Err = err.Error()
		h.logger.Warn("LLM 告警分析失败", zap.Uint64("alert_id", task.AlertID), zap.Error(err))
	} else {
		task.Status = "done"
		task.Result = result
	}
	task.DoneAt = time.Now()
}

// GetAnalysisResult P1-10: 客户端轮询查结果.
// GET /api/v1/alerts/analysis/:task_id
func (h *AlertAnalysisHandler) GetAnalysisResult(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		BadRequest(c, "缺少 task_id")
		return
	}
	h.mu.RLock()
	task, ok := h.tasks[taskID]
	h.mu.RUnlock()
	if !ok {
		NotFound(c, "task not found or expired")
		return
	}
	Success(c, task)
}
