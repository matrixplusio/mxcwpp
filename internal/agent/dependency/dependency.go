// Package dependency 管理 Agent 端外部依赖的安装、卸载和状态检测
package dependency

import (
	"fmt"

	"go.uber.org/zap"
)

// Result 是依赖操作的结果
type Result struct {
	Success bool
	Message string
	Version string
}

// Manager 管理外部依赖
type Manager struct {
	logger     *zap.Logger
	BackendURL string // 后台系统地址，优先从此下载依赖包
}

// NewManager 创建依赖管理器
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{logger: logger}
}

// Execute 执行依赖操作
func (m *Manager) Execute(name, action, version string) Result {
	return Result{Success: false, Message: fmt.Sprintf("unknown dependency: %s", name)}
}
