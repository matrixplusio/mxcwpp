// Package api 提供 Manager HTTP API 处理函数
package api

import (
	"context"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ThreatIntelHandler 威胁情报 API
type ThreatIntelHandler struct {
	service     *biz.ThreatIntel
	redisClient *redis.Client
	logger      *zap.Logger
}

// NewThreatIntelHandler 创建威胁情报 handler
func NewThreatIntelHandler(service *biz.ThreatIntel, redisClient *redis.Client, logger *zap.Logger) *ThreatIntelHandler {
	return &ThreatIntelHandler{service: service, redisClient: redisClient, logger: logger}
}

// GetIOCStats 获取 IOC 统计概览
func (h *ThreatIntelHandler) GetIOCStats(c *gin.Context) {
	if h.redisClient == nil {
		Success(c, gin.H{"ip": 0, "hash": 0, "domain": 0, "url": 0, "total": 0})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	types := []string{"ip", "hash", "domain", "url"}
	stats := gin.H{}
	var total int64

	for _, t := range types {
		count, err := h.redisClient.SCard(ctx, "mxcwpp:ioc:"+t).Result()
		if err != nil {
			count = 0
		}
		stats[t] = count
		total += count
	}
	stats["total"] = total

	Success(c, stats)
}

// ListIOCs 列出指定类型的 IOC
func (h *ThreatIntelHandler) ListIOCs(c *gin.Context) {
	iocType := c.DefaultQuery("type", "ip")
	if h.redisClient == nil {
		Success(c, gin.H{"items": []string{}, "total": 0})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	key := "mxcwpp:ioc:" + iocType
	members, err := h.redisClient.SMembers(ctx, key).Result()
	if err != nil {
		h.logger.Warn("查询 IOC 失败", zap.String("type", iocType), zap.Error(err))
		members = []string{}
	}

	// 简单分页
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	total := len(members)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	Success(c, gin.H{
		"items": members[start:end],
		"total": total,
		"type":  iocType,
	})
}

// CheckIOC 检查单个值是否命中 IOC
func (h *ThreatIntelHandler) CheckIOC(c *gin.Context) {
	var req struct {
		Type  string `json:"type" binding:"required"`
		Value string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	hit := h.service.CheckIOC(c.Request.Context(), req.Type, req.Value)
	Success(c, gin.H{"hit": hit, "type": req.Type, "value": req.Value})
}

// TriggerSync 手动触发 IOC 同步
func (h *ThreatIntelHandler) TriggerSync(c *gin.Context) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := h.service.SyncIOCs(ctx); err != nil {
			h.logger.Error("手动同步 IOC 失败", zap.Error(err))
		}
	}()
	SuccessMessage(c, "IOC 同步已触发")
}

// ListLocalIOCs 列出自有情报
func (h *ThreatIntelHandler) ListLocalIOCs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}
	items, total, err := h.service.ListLocalIOCs(c.Query("type"), page, pageSize)
	if err != nil {
		InternalError(c, "查询自有情报失败")
		return
	}
	SuccessPaginated(c, total, items)
}

// CreateLocalIOC 人工录入一条自有情报
func (h *ThreatIntelHandler) CreateLocalIOC(c *gin.Context) {
	var req struct {
		IOCType     string `json:"ioc_type" binding:"required"`
		Value       string `json:"value" binding:"required"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误: "+err.Error())
		return
	}
	ioc := model.LocalIOC{
		IOCType: req.IOCType, Value: req.Value, Source: "manual",
		Severity: req.Severity, Description: req.Description, CreatedBy: c.GetString("username"),
	}
	if _, err := h.service.AddLocalIOC(c.Request.Context(), ioc); err != nil {
		BadRequest(c, err.Error())
		return
	}
	SuccessMessage(c, "已录入自有情报")
}

// DeleteLocalIOC 删除自有情报
func (h *ThreatIntelHandler) DeleteLocalIOC(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的 ID")
		return
	}
	if err := h.service.DeleteLocalIOC(c.Request.Context(), uint(id)); err != nil {
		InternalError(c, "删除失败: "+err.Error())
		return
	}
	SuccessMessage(c, "已删除")
}

// ConfirmThreat 用户研判真实威胁:解决告警 + 提取 IOC 入自有情报库
func (h *ThreatIntelHandler) ConfirmThreat(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("alert_id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的告警 ID")
		return
	}
	added, err := h.service.ConfirmThreatFromAlert(c.Request.Context(), uint(id), c.GetString("username"))
	if err != nil {
		InternalError(c, "确认失败: "+err.Error())
		return
	}
	Success(c, gin.H{"extracted": added, "extracted_count": len(added)})
}

// GetSyncStatus 获取威胁情报最新同步状态
// GET /api/v1/threat-intel/sync-status
func (h *ThreatIntelHandler) GetSyncStatus(c *gin.Context) {
	record, err := h.service.GetLatestSyncStatus()
	if err != nil {
		h.logger.Error("查询威胁情报同步状态失败", zap.Error(err))
		InternalError(c, "查询同步状态失败")
		return
	}
	if record == nil {
		Success(c, gin.H{"status": "never", "message": "尚未执行过同步"})
		return
	}
	Success(c, record)
}

// GetSyncHistory 获取威胁情报同步历史记录
// GET /api/v1/threat-intel/sync-history
func (h *ThreatIntelHandler) GetSyncHistory(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	records, total, err := h.service.GetSyncHistory(page, pageSize)
	if err != nil {
		h.logger.Error("查询威胁情报同步历史失败", zap.Error(err))
		InternalError(c, "查询同步历史失败")
		return
	}

	Success(c, gin.H{
		"total": total,
		"items": records,
	})
}
