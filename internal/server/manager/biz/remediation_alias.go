// Package biz 提供业务逻辑层
package biz

import "github.com/matrixplusio/mxcwpp/internal/server/remediation"

// 修复任务派发与 Agent 结果/进度处理已下沉到中立共享包
// internal/server/remediation（供 manager / agentcenter / consumer 各服务进程内
// 复用，下游不再反向 import manager/biz）。此处保留别名使 biz 内既有调用零改动。
type (
	RemediationExecutor    = remediation.RemediationExecutor
	RemediationTaskPayload = remediation.RemediationTaskPayload
	PreCheckResultHandler  = remediation.PreCheckResultHandler
)

const (
	RemediationDataType   = remediation.RemediationDataType
	RemediationPluginName = remediation.RemediationPluginName
)

var (
	NewRemediationExecutor   = remediation.NewRemediationExecutor
	NewPreCheckResultHandler = remediation.NewPreCheckResultHandler
)
