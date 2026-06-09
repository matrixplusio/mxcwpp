package api

import (
	"encoding/json"
	"io"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/engine/kube"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// KubeAuditHandler K8s Audit Webhook 接收端
type KubeAuditHandler struct {
	db        *gorm.DB
	logger    *zap.Logger
	processor *kube.KubeAuditProcessor
}

// NewKubeAuditHandler 创建 Audit Webhook Handler
func NewKubeAuditHandler(db *gorm.DB, logger *zap.Logger, alarmService *kube.KubeAlarmService) *KubeAuditHandler {
	return &KubeAuditHandler{
		db:        db,
		logger:    logger,
		processor: kube.NewKubeAuditProcessor(db, logger, alarmService),
	}
}

// AuditEvent K8s Audit Event 简化结构
type AuditEvent = model.AuditEvent

// AuditUser Audit 事件中的用户信息
type AuditUser = model.AuditUser

// AuditObjectRef Audit 事件中的对象引用
type AuditObjectRef = model.AuditObjectRef

// AuditEventList K8s Audit EventList
type AuditEventList = model.AuditEventList

// ReceiveAuditWebhook 接收 K8s apiserver 的 audit webhook 回调
func (h *KubeAuditHandler) ReceiveAuditWebhook(c *gin.Context) {
	token := c.Param("cluster_token")
	if token == "" {
		Unauthorized(c, "missing token")
		return
	}

	// 通过 token 查找集群
	var cluster model.KubeCluster
	if err := h.db.Where("audit_token = ?", token).First(&cluster).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			Unauthorized(c, "invalid token")
			return
		}
		h.logger.Error("查询集群失败", zap.Error(err))
		InternalError(c, "internal error")
		return
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 10<<20)) // 10MB limit
	if err != nil {
		h.logger.Error("读取 audit webhook body 失败", zap.Error(err))
		BadRequest(c, "read body failed")
		return
	}

	var eventList AuditEventList
	if err := json.Unmarshal(body, &eventList); err != nil {
		// 尝试解析为单个事件
		var single AuditEvent
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			h.logger.Error("解析 audit event 失败", zap.Error(err))
			BadRequest(c, "invalid audit event")
			return
		}
		eventList.Items = []AuditEvent{single}
	}

	go h.processAuditEvents(cluster, eventList.Items)

	// K8s audit webhook ack：返回处理的事件数（K8s 仅检 2xx，body 仅供调试）
	Success(c, gin.H{"received": len(eventList.Items)})
}

// processAuditEvents 异步处理 audit 事件（委托给 KubeAuditProcessor）
func (h *KubeAuditHandler) processAuditEvents(cluster model.KubeCluster, events []AuditEvent) {
	h.processor.ProcessAuditEvents(cluster, events)
}
