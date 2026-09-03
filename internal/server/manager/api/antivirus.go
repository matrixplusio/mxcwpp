package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// AntivirusHandler 病毒查杀 API 处理器
type AntivirusHandler struct {
	db             *gorm.DB
	logger         *zap.Logger
	virusDBUpdater *biz.VirusDBUpdater
	acDispatcher   *sd.ACDispatcher
}

// NewAntivirusHandler 创建病毒查杀处理器
func NewAntivirusHandler(db *gorm.DB, logger *zap.Logger, virusDBUpdater *biz.VirusDBUpdater, acDispatcher *sd.ACDispatcher) *AntivirusHandler {
	return &AntivirusHandler{db: db, logger: logger, virusDBUpdater: virusDBUpdater, acDispatcher: acDispatcher}
}

// ---------- 扫描任务 CRUD ----------

// ListTasks 获取扫描任务列表
// GET /api/v1/antivirus/tasks
func (h *AntivirusHandler) ListTasks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	query := h.db.Model(&model.AntivirusScanTask{})

	if keyword := strings.TrimSpace(c.Query("keyword")); keyword != "" {
		pattern := "%" + keyword + "%"
		query = query.Where("name LIKE ? OR created_by LIKE ?", pattern, pattern)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if scanType := strings.TrimSpace(c.Query("scan_type")); scanType != "" {
		query = query.Where("scan_type = ?", scanType)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询扫描任务总数失败", zap.Error(err))
		InternalError(c, "查询扫描任务失败")
		return
	}

	var tasks []model.AntivirusScanTask
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&tasks).Error; err != nil {
		h.logger.Error("查询扫描任务列表失败", zap.Error(err))
		InternalError(c, "查询扫描任务失败")
		return
	}

	Success(c, gin.H{
		"total": total,
		"items": tasks,
	})
}

// GetTask 获取扫描任务详情
// GET /api/v1/antivirus/tasks/:id
func (h *AntivirusHandler) GetTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	var task model.AntivirusScanTask
	if err := h.db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "扫描任务不存在")
			return
		}
		h.logger.Error("查询扫描任务失败", zap.Error(err))
		InternalError(c, "查询扫描任务失败")
		return
	}

	Success(c, task)
}

// CreateAntivirusTaskRequest 创建扫描任务请求
type CreateAntivirusTaskRequest struct {
	Name      string   `json:"name" binding:"required"`
	ScanType  string   `json:"scanType" binding:"required,oneof=quick full custom"`
	ScanPaths []string `json:"scanPaths"`
	HostIDs   []string `json:"hostIds" binding:"required,min=1"`
}

// CreateTask 创建扫描任务
// POST /api/v1/antivirus/tasks
func (h *AntivirusHandler) CreateTask(c *gin.Context) {
	var req CreateAntivirusTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if req.ScanType == "custom" && len(req.ScanPaths) == 0 {
		BadRequest(c, "自定义扫描模式必须指定扫描路径")
		return
	}

	// 获取当前用户
	createdBy, _ := c.Get("username")
	createdByStr, _ := createdBy.(string)

	task := model.AntivirusScanTask{
		Name:       req.Name,
		ScanType:   req.ScanType,
		ScanPaths:  req.ScanPaths,
		HostIDs:    req.HostIDs,
		Status:     "pending",
		TotalHosts: len(req.HostIDs),
		CreatedBy:  createdByStr,
	}

	if err := h.db.Create(&task).Error; err != nil {
		h.logger.Error("创建扫描任务失败", zap.Error(err))
		InternalError(c, "创建扫描任务失败")
		return
	}

	h.logger.Info("创建扫描任务",
		zap.Uint("task_id", task.ID),
		zap.String("name", task.Name),
		zap.String("scan_type", task.ScanType),
		zap.Int("host_count", len(req.HostIDs)),
	)

	Created(c, task)
}

// DeleteTask 删除扫描任务
// DELETE /api/v1/antivirus/tasks/:id
func (h *AntivirusHandler) DeleteTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	var task model.AntivirusScanTask
	if err := h.db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "扫描任务不存在")
			return
		}
		h.logger.Error("查询扫描任务失败", zap.Error(err))
		InternalError(c, "查询扫描任务失败")
		return
	}

	if task.Status == "running" {
		BadRequest(c, "运行中的任务不能删除，请先取消")
		return
	}

	txErr := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("task_id = ?", task.ID).Delete(&model.AntivirusScanResult{}).Error; err != nil {
			return err
		}
		return tx.Delete(&task).Error
	})
	if txErr != nil {
		h.logger.Error("删除扫描任务失败", zap.Uint("id", task.ID), zap.Error(txErr))
		InternalError(c, "删除扫描任务失败")
		return
	}

	h.logger.Info("删除扫描任务", zap.Uint("task_id", task.ID))
	SuccessMessage(c, "扫描任务已删除")
}

// CancelTask 取消扫描任务
// POST /api/v1/antivirus/tasks/:id/cancel
func (h *AntivirusHandler) CancelTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	var task model.AntivirusScanTask
	if err := h.db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "扫描任务不存在")
			return
		}
		h.logger.Error("查询扫描任务失败", zap.Error(err))
		InternalError(c, "查询扫描任务失败")
		return
	}

	if task.Status != "pending" && task.Status != "running" {
		BadRequest(c, "只能取消待执行或运行中的任务")
		return
	}

	now := model.LocalTime(time.Now())
	if err := h.db.Model(&task).Updates(map[string]interface{}{
		"status":      "cancelled",
		"finished_at": &now,
	}).Error; err != nil {
		h.logger.Error("取消扫描任务失败", zap.Uint("id", task.ID), zap.Error(err))
		InternalError(c, "取消扫描任务失败")
		return
	}

	h.logger.Info("取消扫描任务", zap.Uint("task_id", task.ID))
	SuccessMessage(c, "扫描任务已取消")
}

// ---------- 扫描结果查询 ----------

// ListResults 获取扫描结果列表
// GET /api/v1/antivirus/results
func (h *AntivirusHandler) ListResults(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	query := h.db.Model(&model.AntivirusScanResult{})

	if taskID := strings.TrimSpace(c.Query("task_id")); taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if hostID := strings.TrimSpace(c.Query("host_id")); hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if severity := strings.TrimSpace(c.Query("severity")); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if threatType := strings.TrimSpace(c.Query("threat_type")); threatType != "" {
		query = query.Where("threat_type = ?", threatType)
	}
	if action := strings.TrimSpace(c.Query("action")); action != "" {
		query = query.Where("action = ?", action)
	}
	if keyword := strings.TrimSpace(c.Query("keyword")); keyword != "" {
		pattern := "%" + keyword + "%"
		query = query.Where("threat_name LIKE ? OR file_path LIKE ? OR hostname LIKE ? OR ip LIKE ?", pattern, pattern, pattern, pattern)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询扫描结果总数失败", zap.Error(err))
		InternalError(c, "查询扫描结果失败")
		return
	}

	var results []model.AntivirusScanResult
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("detected_at DESC").Find(&results).Error; err != nil {
		h.logger.Error("查询扫描结果列表失败", zap.Error(err))
		InternalError(c, "查询扫描结果失败")
		return
	}

	Success(c, gin.H{
		"total": total,
		"items": results,
	})
}

// GetResult 获取扫描结果详情
// GET /api/v1/antivirus/results/:id
func (h *AntivirusHandler) GetResult(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的结果 ID")
		return
	}

	var result model.AntivirusScanResult
	if err := h.db.First(&result, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "扫描结果不存在")
			return
		}
		h.logger.Error("查询扫描结果失败", zap.Error(err))
		InternalError(c, "查询扫描结果失败")
		return
	}

	Success(c, result)
}

// QuarantineResult 隔离威胁文件
// POST /api/v1/antivirus/results/:id/quarantine
func (h *AntivirusHandler) QuarantineResult(c *gin.Context) {
	h.updateResultAction(c, "quarantined", "隔离", "quarantine")
}

// IgnoreResult 忽略威胁
// POST /api/v1/antivirus/results/:id/ignore
func (h *AntivirusHandler) IgnoreResult(c *gin.Context) {
	h.updateResultAction(c, "ignored", "忽略", "")
}

// DeleteFileResult 删除威胁文件
// POST /api/v1/antivirus/results/:id/delete-file
func (h *AntivirusHandler) DeleteFileResult(c *gin.Context) {
	h.updateResultAction(c, "deleted", "删除", "delete")
}

func (h *AntivirusHandler) updateResultAction(c *gin.Context, action string, label string, agentAction string) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的结果 ID")
		return
	}

	var result model.AntivirusScanResult
	if err := h.db.First(&result, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "扫描结果不存在")
			return
		}
		h.logger.Error("查询扫描结果失败", zap.Error(err))
		InternalError(c, "查询扫描结果失败")
		return
	}

	if err := h.db.Model(&result).Update("action", action).Error; err != nil {
		h.logger.Error(label+"威胁失败", zap.Uint("id", result.ID), zap.Error(err))
		InternalError(c, label+"威胁失败")
		return
	}

	// 需要 Agent 执行文件操作的动作（quarantine/delete），下发 DataType 7003 到 Agent
	if agentAction != "" && h.acDispatcher != nil {
		h.dispatchQuarantineCmd(&result, agentAction)
	}

	h.logger.Info(label+"威胁",
		zap.Uint("result_id", result.ID),
		zap.String("threat_name", result.ThreatName),
		zap.String("file_path", result.FilePath),
	)
	SuccessMessage(c, "威胁已"+label)
}

// dispatchQuarantineCmd 下发隔离/删除命令到 Agent（DataType 7003）
func (h *AntivirusHandler) dispatchQuarantineCmd(result *model.AntivirusScanResult, action string) {
	taskData, _ := json.Marshal(map[string]string{
		"task_id":   fmt.Sprintf("%d", result.ID),
		"file_path": result.FilePath,
		"file_hash": result.FileHash,
		"action":    action,
	})

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			DataType:   7003,
			ObjectName: "scanner",
			Data:       string(taskData),
			Token:      fmt.Sprintf("q-%d", result.ID),
		}},
	}

	if err := h.acDispatcher.SendCommand(result.HostID, cmd); err != nil {
		h.logger.Error("下发隔离命令到 Agent 失败",
			zap.Uint("result_id", result.ID),
			zap.String("host_id", result.HostID),
			zap.Error(err))
	} else {
		h.logger.Info("隔离命令已下发到 Agent",
			zap.Uint("result_id", result.ID),
			zap.String("host_id", result.HostID),
			zap.String("action", action))
	}
}

// ---------- 统计 ----------

// GetStatistics 获取病毒查杀统计概览
// GET /api/v1/antivirus/statistics
func (h *AntivirusHandler) GetStatistics(c *gin.Context) {
	var taskStats struct {
		Total     int64 `gorm:"column:total"`
		Running   int64 `gorm:"column:running"`
		Completed int64 `gorm:"column:completed"`
	}
	h.db.Model(&model.AntivirusScanTask{}).Select(
		"COUNT(*) as total",
		"SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running",
		"SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed",
	).Scan(&taskStats)

	var resultStats struct {
		Total       int64 `gorm:"column:total"`
		Detected    int64 `gorm:"column:detected"`
		Quarantined int64 `gorm:"column:quarantined"`
		Deleted     int64 `gorm:"column:deleted"`
		Ignored     int64 `gorm:"column:ignored"`
	}
	h.db.Model(&model.AntivirusScanResult{}).Select(
		"COUNT(*) as total",
		"SUM(CASE WHEN action = 'detected' THEN 1 ELSE 0 END) as detected",
		"SUM(CASE WHEN action = 'quarantined' THEN 1 ELSE 0 END) as quarantined",
		"SUM(CASE WHEN action = 'deleted' THEN 1 ELSE 0 END) as deleted",
		"SUM(CASE WHEN action = 'ignored' THEN 1 ELSE 0 END) as ignored",
	).Scan(&resultStats)

	var severityRows []struct {
		Severity string `gorm:"column:severity"`
		Count    int64  `gorm:"column:count"`
	}
	h.db.Model(&model.AntivirusScanResult{}).
		Where("action = ?", "detected").
		Select("severity, COUNT(*) as count").
		Group("severity").
		Scan(&severityRows)

	severityMap := make(map[string]int64)
	for _, row := range severityRows {
		severityMap[row.Severity] = row.Count
	}

	var affectedHosts int64
	h.db.Model(&model.AntivirusScanResult{}).
		Where("action = ?", "detected").
		Distinct("host_id").
		Count(&affectedHosts)

	Success(c, gin.H{
		"tasks": gin.H{
			"total":     taskStats.Total,
			"running":   taskStats.Running,
			"completed": taskStats.Completed,
		},
		"threats": gin.H{
			"total":       resultStats.Total,
			"detected":    resultStats.Detected,
			"quarantined": resultStats.Quarantined,
			"deleted":     resultStats.Deleted,
			"ignored":     resultStats.Ignored,
		},
		"severity": gin.H{
			"critical": severityMap["critical"],
			"high":     severityMap["high"],
			"medium":   severityMap["medium"],
			"low":      severityMap["low"],
		},
		"affectedHosts": affectedHosts,
	})
}

// ---------- 病毒库同步状态 ----------

// GetVirusDBStatus 获取病毒库最新同步状态
// GET /api/v1/antivirus/virus-db/status
func (h *AntivirusHandler) GetVirusDBStatus(c *gin.Context) {
	record, err := h.virusDBUpdater.GetLatestStatus("clamav")
	if err != nil {
		h.logger.Error("查询病毒库同步状态失败", zap.Error(err))
		InternalError(c, "查询同步状态失败")
		return
	}
	if record == nil {
		Success(c, gin.H{"status": "never", "message": "尚未执行过同步"})
		return
	}
	Success(c, record)
}

// GetVirusDBHistory 获取病毒库同步历史记录
// GET /api/v1/antivirus/virus-db/history
func (h *AntivirusHandler) GetVirusDBHistory(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	records, total, err := h.virusDBUpdater.GetSyncHistory("clamav", page, pageSize)
	if err != nil {
		h.logger.Error("查询病毒库同步历史失败", zap.Error(err))
		InternalError(c, "查询同步历史失败")
		return
	}

	Success(c, gin.H{
		"total": total,
		"items": records,
	})
}

// TriggerVirusDBSync 手动触发病毒库同步
// POST /api/v1/antivirus/virus-db/sync
func (h *AntivirusHandler) TriggerVirusDBSync(c *gin.Context) {
	if ok := h.virusDBUpdater.TriggerSync(); !ok {
		BadRequest(c, "已有同步任务在排队中，请稍后再试")
		return
	}
	h.logger.Info("手动触发病毒库同步")
	SuccessMessage(c, "同步任务已触发")
}
