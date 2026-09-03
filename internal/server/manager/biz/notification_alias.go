// Package biz 提供业务逻辑层
package biz

import "github.com/matrixplusio/mxcwpp/internal/server/notify"

// 通知派发已下沉到中立共享包 internal/server/notify（供 manager / agentcenter /
// engine / consumer 各服务进程内复用，不再令下游模块反向 import manager/biz）。
// 此处保留类型与构造别名，使 biz 内既有调用零改动。
type (
	NotificationService = notify.NotificationService
	AlertData           = notify.AlertData
	AlertResolvedData   = notify.AlertResolvedData
	AgentOnlineData     = notify.AgentOnlineData
	AgentOfflineData    = notify.AgentOfflineData
	DetectionAlertData  = notify.DetectionAlertData
	FIMAlertData        = notify.FIMAlertData
	VirusAlertData      = notify.VirusAlertData
	KubeAlertData       = notify.KubeAlertData
)

// NewNotificationService 构造通知服务（别名转发到 notify 包）。
var NewNotificationService = notify.NewNotificationService
