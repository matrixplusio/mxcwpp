package biz

import (
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/kube"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// KubeAlarmNotifier 实现 kube.AlarmNotifier interface,
// 把 engine/kube 产出的告警转换成 biz.KubeAlertData 并通过 NotificationService 派发。
//
// 该 adapter 让 engine/kube 不依赖 manager/biz,
// 反向通过 kube.SetNotifier 注入。
type KubeAlarmNotifier struct {
	notify *NotificationService
	logger *zap.Logger
}

// NewKubeAlarmNotifier 构造 notifier adapter。
func NewKubeAlarmNotifier(db *gorm.DB, logger *zap.Logger) *KubeAlarmNotifier {
	return &KubeAlarmNotifier{
		notify: NewNotificationService(db, logger),
		logger: logger,
	}
}

// NotifyKubeAlarm 实现 kube.AlarmNotifier interface。
func (n *KubeAlarmNotifier) NotifyKubeAlarm(alarm *model.KubeAlarm) {
	if err := n.notify.SendKubeAlertNotification(&KubeAlertData{
		ClusterName: alarm.ClusterName,
		Severity:    alarm.Severity,
		AlarmType:   string(alarm.AlarmType),
		Title:       alarm.Title,
		Description: alarm.Description,
		Message:     alarm.Message,
		Namespace:   alarm.Namespace,
		Target:      alarm.Target,
	}); err != nil {
		n.logger.Error("发送 K8s 告警通知失败", zap.Error(err))
	}
}

// 编译期断言: KubeAlarmNotifier 实现 kube.AlarmNotifier
var _ kube.AlarmNotifier = (*KubeAlarmNotifier)(nil)
