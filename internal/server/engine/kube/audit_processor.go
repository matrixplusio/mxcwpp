package kube

import (
	"encoding/json"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// KubeAuditProcessor 审计事件处理器（Webhook 和 Pub/Sub 共用）
type KubeAuditProcessor struct {
	db           *gorm.DB
	logger       *zap.Logger
	alarmService *KubeAlarmService
	detector     *KubeDetector
}

// NewKubeAuditProcessor 创建审计事件处理器
func NewKubeAuditProcessor(db *gorm.DB, logger *zap.Logger, alarmService *KubeAlarmService) *KubeAuditProcessor {
	return &KubeAuditProcessor{
		db:           db,
		logger:       logger,
		alarmService: alarmService,
		detector:     NewKubeDetector(db, logger, alarmService),
	}
}

// ProcessAuditEvents 处理审计事件列表：创建 KubeEvent 记录 + 规则引擎检测生成告警
func (p *KubeAuditProcessor) ProcessAuditEvents(cluster model.KubeCluster, events []model.AuditEvent) {
	for _, event := range events {
		// 只处理 ResponseComplete 阶段，避免重复
		if event.Stage != "" && event.Stage != "ResponseComplete" {
			continue
		}

		rawData, err := json.Marshal(event)
		if err != nil {
			p.logger.Warn("序列化审计事件失败", zap.Error(err))
			continue
		}

		kubeEvent := model.KubeEvent{
			ClusterID:   cluster.ID,
			ClusterName: cluster.Name,
			EventType:   "audit",
			Severity:    classifyAuditSeverity(&event),
			Title:       buildAuditTitle(&event),
			Message:     buildAuditMessage(&event),
			RawData:     model.RawJSON(rawData),
			Status:      model.KubeEventStatusUnhandled,
		}

		if event.ObjectRef != nil {
			kubeEvent.Namespace = event.ObjectRef.Namespace
		}
		if len(event.SourceIPs) > 0 {
			kubeEvent.SourceIP = event.SourceIPs[0]
		}

		if err := p.db.Create(&kubeEvent).Error; err != nil {
			p.logger.Error("保存 audit event 失败", zap.Error(err))
		}

		// 规则引擎检测
		p.detector.DetectAuditEvent(cluster.ID, cluster.Name, &event)
	}
}

func classifyAuditSeverity(event *model.AuditEvent) string {
	if event.ObjectRef == nil {
		return "info"
	}
	if event.ObjectRef.Subresource == "exec" {
		return "high"
	}
	if event.ObjectRef.Resource == "secrets" && (event.Verb == "get" || event.Verb == "list") {
		return "medium"
	}
	if event.ObjectRef.Resource == "clusterrolebindings" && event.Verb == "create" {
		return "high"
	}
	return "info"
}

func buildAuditTitle(event *model.AuditEvent) string {
	if event.ObjectRef == nil {
		return event.Verb + " " + event.RequestURI
	}
	title := event.Verb + " " + event.ObjectRef.Resource
	if event.ObjectRef.Subresource != "" {
		title += "/" + event.ObjectRef.Subresource
	}
	if event.ObjectRef.Name != "" {
		title += " " + event.ObjectRef.Name
	}
	return title
}

func buildAuditMessage(event *model.AuditEvent) string {
	msg := "User: " + event.User.Username
	if event.ObjectRef != nil && event.ObjectRef.Namespace != "" {
		msg += ", Namespace: " + event.ObjectRef.Namespace
	}
	if event.UserAgent != "" {
		msg += ", UserAgent: " + event.UserAgent
	}
	return msg
}
