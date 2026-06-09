package engine

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/engine/kube"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// KubeAuditStage 接入 engine/kube.KubeDetector,
// 把 K8s Audit Event 喂给检测引擎,内部规则命中由 KubeAlarmService 派发。
//
// 由于 KubeDetector 直接走 KubeAlarmService 写 kube_alarms 表 + 通知,
// 本 Stage 不返回 Alert 数组 (告警已由 alarm service 异步派发)。
// 后续 PR 可改造 KubeDetector 暴露 Alert chan, 让 Engine Pipeline 也接管。
type KubeAuditStage struct {
	detector *kube.KubeDetector
	logger   *zap.Logger
}

// NewKubeAuditStage 构造 K8s audit stage。
func NewKubeAuditStage(d *kube.KubeDetector, logger *zap.Logger) *KubeAuditStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &KubeAuditStage{detector: d, logger: logger}
}

// Name 满足 Stage interface。
func (s *KubeAuditStage) Name() string { return "kube_audit" }

// Process 仅处理 K8s audit 类事件 (DataType 5070-5099 K8s 资产 / 7080-7099 K8s alarm)。
//
// ev.Payload 应可解码为 model.AuditEvent。
func (s *KubeAuditStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if s.detector == nil {
		return nil, nil
	}
	if ev.DataType < 5070 || ev.DataType > 7099 {
		return nil, nil
	}

	var audit model.AuditEvent
	if err := json.Unmarshal(ev.Payload, &audit); err != nil {
		s.logger.Debug("kube audit decode payload failed", zap.Error(err))
		return nil, nil
	}

	// clusterID + clusterName 应在 ev 顶层字段中 (后续 PR 加 ev.ClusterID)
	fields, _ := payloadToFields(ev.Payload)
	var clusterID uint
	if v := fields["cluster_id"]; v != "" {
		var i uint
		for _, c := range v {
			if c < '0' || c > '9' {
				break
			}
			i = i*10 + uint(c-'0')
		}
		clusterID = i
	}
	clusterName := fields["cluster_name"]

	s.detector.DetectAuditEvent(clusterID, clusterName, &audit)
	return nil, nil
}

var _ Stage = (*KubeAuditStage)(nil)
