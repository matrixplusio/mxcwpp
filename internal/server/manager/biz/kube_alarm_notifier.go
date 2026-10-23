package biz

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/engine/kube"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// KubeAlarmNotifier 实现 kube.AlarmNotifier interface，把 engine/kube 产出的告警发布到统一通知出口。
//
// 该 adapter 让 engine/kube 不依赖 manager，反向通过 kube.SetNotifier 注入。
type KubeAlarmNotifier struct {
	logger *zap.Logger
}

// NewKubeAlarmNotifier 构造 notifier adapter。
func NewKubeAlarmNotifier(_ *gorm.DB, logger *zap.Logger) *KubeAlarmNotifier {
	return &KubeAlarmNotifier{logger: logger}
}

// NotifyKubeAlarm 实现 kube.AlarmNotifier interface。
// K8s 告警没有主机维度，只会命中主机范围为「全局」的通知配置。
func (n *KubeAlarmNotifier) NotifyKubeAlarm(alarm *model.KubeAlarm) {
	var lines []string
	if alarm.Description != "" {
		lines = append(lines, alarm.Description)
	}
	for _, kv := range [][2]string{
		{"集群", alarm.ClusterName}, {"命名空间", alarm.Namespace}, {"对象", alarm.Target}, {"详情", alarm.Message},
	} {
		if kv[1] != "" {
			lines = append(lines, fmt.Sprintf("**%s：** %s", kv[0], kv[1]))
		}
	}
	alertbus.Publish(alertbus.Event{
		Category: model.NotifyCategoryKubeAlert, Source: "kube_runtime",
		Severity: alarm.Severity, Title: alarm.Title, Description: strings.Join(lines, "\n"),
		DedupKey: "kube|" + alarm.Fingerprint, RefTable: "kube_alarms", RefID: fmt.Sprint(alarm.ID),
		OccurredAt: alarm.LastSeenAt.Time(),
	})
}

// 编译期断言: KubeAlarmNotifier 实现 kube.AlarmNotifier
var _ kube.AlarmNotifier = (*KubeAlarmNotifier)(nil)
