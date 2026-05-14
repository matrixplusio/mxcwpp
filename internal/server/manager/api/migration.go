package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/migration/mvp1"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// MigrationHandler 迁移助手 API 处理器
type MigrationHandler struct {
	db     *gorm.DB
	logger *zap.Logger
	mu     sync.Mutex
	cancel context.CancelFunc
}

// NewMigrationHandler 创建迁移处理器
func NewMigrationHandler(db *gorm.DB, logger *zap.Logger) *MigrationHandler {
	return &MigrationHandler{db: db, logger: logger}
}

// TestConnection 测试与 MVP1 的连接
// POST /api/v1/system/migration/test-connection
func (h *MigrationHandler) TestConnection(c *gin.Context) {
	var req struct {
		URL      string `json:"url" binding:"required"`
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请填写完整的连接信息")
		return
	}

	client, err := mvp1.NewClient(req.URL, req.Username, req.Password)
	if err != nil {
		h.logger.Warn("连接 MVP1 失败", zap.Error(err))
		BadRequest(c, "连接失败")
		return
	}

	version, _ := client.Version()

	// 统计各表记录数
	tablePaths := map[string]string{
		"users":          "/api/v1/users",
		"business_lines": "/api/v1/business-lines",
		"hosts":          "/api/v1/hosts",
		"policies":       "/api/v1/policies",
		"scan_tasks":     "/api/v1/tasks",
		"scan_results":   "/api/v1/results",
		"notifications":  "/api/v1/notifications",
	}

	tables := make(map[string]int64)
	for name, path := range tablePaths {
		count, err := client.CountTable(path)
		if err != nil {
			h.logger.Warn("统计 MVP1 表记录数失败", zap.String("table", name), zap.Error(err))
			tables[name] = -1
			continue
		}
		tables[name] = count
	}

	Success(c, gin.H{
		"version": version,
		"tables":  tables,
	})
}

// StartJob 创建并启动迁移任务
// POST /api/v1/system/migration/jobs
func (h *MigrationHandler) StartJob(c *gin.Context) {
	var req struct {
		URL      string   `json:"url" binding:"required"`
		Username string   `json:"username" binding:"required"`
		Password string   `json:"password" binding:"required"`
		Scope    []string `json:"scope" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	// 验证 scope
	validScopes := map[string]bool{
		"users": true, "business_lines": true, "hosts": true,
		"policies": true, "rules": true, "scan_tasks": true,
		"scan_results": true, "notifications": true,
	}
	for _, s := range req.Scope {
		if !validScopes[s] {
			BadRequest(c, fmt.Sprintf("无效的迁移范围: %s", s))
			return
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// 检查是否有运行中的任务
	var runningCount int64
	h.db.Model(&model.MigrationJob{}).Where("status = ?", "running").Count(&runningCount)
	if runningCount > 0 {
		Conflict(c, "已有迁移任务正在运行")
		return
	}

	// 先建立连接验证凭据
	client, err := mvp1.NewClient(req.URL, req.Username, req.Password)
	if err != nil {
		h.logger.Warn("连接 MVP1 数据库失败", zap.Error(err))
		BadRequest(c, "连接 MVP1 数据库失败")
		return
	}

	// 获取操作者 ID
	var operatorID uint
	if uid, exists := c.Get("user_id"); exists {
		if id, ok := uid.(uint); ok {
			operatorID = id
		}
	}

	job := model.MigrationJob{
		SourceURL:  req.URL,
		SourceUser: req.Username,
		Scope:      model.StringArray(req.Scope),
		Status:     "pending",
		OperatorID: operatorID,
	}
	if err := h.db.Create(&job).Error; err != nil {
		h.logger.Error("创建迁移任务失败", zap.Error(err))
		InternalError(c, "创建迁移任务失败")
		return
	}

	// 后台运行迁移
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	importer := mvp1.NewImporter(client, h.db, h.logger, &job)
	go func() {
		defer cancel()
		importer.Run(ctx)
	}()

	h.logger.Info("迁移任务已启动",
		zap.Uint("job_id", job.ID),
		zap.String("source", req.URL),
		zap.Strings("scope", req.Scope))

	Created(c, job)
}

// ListJobs 列出历史迁移任务
// GET /api/v1/system/migration/jobs
func (h *MigrationHandler) ListJobs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	var total int64
	h.db.Model(&model.MigrationJob{}).Count(&total)

	var jobs []model.MigrationJob
	offset := (page - 1) * pageSize
	if err := h.db.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&jobs).Error; err != nil {
		h.logger.Error("查询迁移任务列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 解析 scope JSON 给前端（Scope 字段已是 StringArray，会自动序列化）
	type jobItem struct {
		model.MigrationJob
		ReportData []mvp1.TableReport `json:"report_data,omitempty"`
	}
	items := make([]jobItem, 0, len(jobs))
	for _, j := range jobs {
		item := jobItem{MigrationJob: j}
		if j.Report != "" {
			_ = json.Unmarshal([]byte(j.Report), &item.ReportData)
		}
		items = append(items, item)
	}

	SuccessPaginated(c, total, items)
}

// GetJob 获取迁移任务详情
// GET /api/v1/system/migration/jobs/:id
func (h *MigrationHandler) GetJob(c *gin.Context) {
	id := c.Param("id")
	var job model.MigrationJob
	if err := h.db.First(&job, id).Error; err != nil {
		NotFound(c, "迁移任务不存在")
		return
	}

	var reportData []mvp1.TableReport
	if job.Report != "" {
		_ = json.Unmarshal([]byte(job.Report), &reportData)
	}

	Success(c, gin.H{
		"id":            job.ID,
		"source_url":    job.SourceURL,
		"source_user":   job.SourceUser,
		"scope":         job.Scope,
		"status":        job.Status,
		"progress":      job.Progress,
		"current_table": job.CurrentTable,
		"total_records": job.TotalRecords,
		"created_count": job.CreatedCount,
		"skipped_count": job.SkippedCount,
		"failed_count":  job.FailedCount,
		"report_data":   reportData,
		"error":         job.Error,
		"operator_id":   job.OperatorID,
		"started_at":    job.StartedAt,
		"finished_at":   job.FinishedAt,
		"created_at":    job.CreatedAt,
		"updated_at":    job.UpdatedAt,
	})
}

// CancelJob 取消运行中的迁移任务
// POST /api/v1/system/migration/jobs/:id/cancel
func (h *MigrationHandler) CancelJob(c *gin.Context) {
	id := c.Param("id")
	var job model.MigrationJob
	if err := h.db.First(&job, id).Error; err != nil {
		NotFound(c, "迁移任务不存在")
		return
	}

	if job.Status != "running" && job.Status != "pending" {
		BadRequest(c, "任务不在运行中")
		return
	}

	h.mu.Lock()
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
	h.mu.Unlock()

	h.db.Model(&job).Updates(map[string]interface{}{
		"status": "cancelled",
		"error":  "用户取消",
	})

	SuccessMessage(c, "已取消")
}
