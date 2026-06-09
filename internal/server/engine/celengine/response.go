// Package celengine - C4: 自动响应
// 规则匹配后通过 AgentCenter 下发 kill/隔离 Task
package celengine

import (
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ResponseAction 自动响应动作
type ResponseAction struct {
	Type   string `json:"type"`   // kill_process, quarantine_file, block_ip
	Target string `json:"target"` // PID / 文件路径 / IP
}

// ResponseRule 自动响应规则
type ResponseRule struct {
	RuleID  uint             `json:"rule_id"`
	Actions []ResponseAction `json:"actions"`
}

// AutoResponder 自动响应执行器
type AutoResponder struct {
	// dispatcher 接口用于向 Agent 下发命令
	dispatcher interface {
		SendCommand(agentID string, cmd interface{}) error
	}
	db     *gorm.DB
	logger *zap.Logger
}

// NewAutoResponder 创建自动响应执行器
func NewAutoResponder(db *gorm.DB, logger *zap.Logger) *AutoResponder {
	return &AutoResponder{
		db:     db,
		logger: logger,
	}
}

// SetDispatcher 设置命令下发器
func (r *AutoResponder) SetDispatcher(dispatcher interface {
	SendCommand(agentID string, cmd interface{}) error
}) {
	r.dispatcher = dispatcher
}

// Execute 执行自动响应
func (r *AutoResponder) Execute(hostID string, matchedRules []model.DetectionRule, fields map[string]string) {
	if r.dispatcher == nil {
		return
	}

	for _, rule := range matchedRules {
		actions := r.determineActions(rule, fields)
		for _, action := range actions {
			err := r.executeAction(hostID, action, fields)
			status := "success"
			errMsg := ""
			if err != nil {
				status = "failed"
				errMsg = err.Error()
				r.logger.Error("自动响应执行失败",
					zap.String("host_id", hostID),
					zap.String("action", action.Type),
					zap.Error(err))
			}
			// 写入审计日志
			r.writeAuditLog(hostID, rule, action, status, errMsg)
		}
	}
}

// writeAuditLog 记录自动响应审计日志
func (r *AutoResponder) writeAuditLog(hostID string, rule model.DetectionRule, action ResponseAction, status string, errMsg string) {
	if r.db == nil {
		r.logger.Warn("审计日志写入跳过: 数据库连接未初始化",
			zap.String("host_id", hostID),
			zap.String("action", action.Type),
			zap.String("rule", rule.Name))
		return
	}
	detail := fmt.Sprintf("rule=%s severity=%s target=%s status=%s", rule.Name, rule.Severity, action.Target, status)
	if errMsg != "" {
		detail += " error=" + errMsg
	}
	log := &model.AuditLog{
		Username:     "system/auto-response",
		Action:       action.Type,
		ResourceType: "auto_response",
		ResourceID:   fmt.Sprintf("%d", rule.ID),
		Detail:       detail,
		Path:         fmt.Sprintf("/host/%s/%s/%s", hostID, action.Type, action.Target),
		IP:           "127.0.0.1",
		StatusCode:   200,
	}
	if status == "failed" {
		log.StatusCode = 500
	}
	if err := r.db.Create(log).Error; err != nil {
		r.logger.Error("自动响应审计日志写入失败",
			zap.String("detail", detail),
			zap.Error(err))
	}
}

// determineActions 根据规则和事件上下文确定响应动作
func (r *AutoResponder) determineActions(rule model.DetectionRule, fields map[string]string) []ResponseAction {
	var actions []ResponseAction

	// 只有 critical 级别规则触发自动响应
	if rule.Severity != "critical" {
		return actions
	}

	// 根据事件类型决定动作
	if pid := fields["pid"]; pid != "" {
		actions = append(actions, ResponseAction{
			Type:   "kill_process",
			Target: pid,
		})
	}

	if filePath := fields["file_path"]; filePath != "" {
		actions = append(actions, ResponseAction{
			Type:   "quarantine_file",
			Target: filePath,
		})
	}

	// 网络阻断：检测到外连恶意 IP 时阻断
	if remoteIP := fields["remote_ip"]; remoteIP != "" {
		actions = append(actions, ResponseAction{
			Type:   "block_ip",
			Target: remoteIP,
		})
	}

	return actions
}

// executeAction 执行单个响应动作
func (r *AutoResponder) executeAction(hostID string, action ResponseAction, fields map[string]string) error {
	taskData := map[string]interface{}{
		"action":  action.Type,
		"target":  action.Target,
		"trigger": "auto_response",
	}
	taskJSON, _ := json.Marshal(taskData)

	r.logger.Info("执行自动响应",
		zap.String("host_id", hostID),
		zap.String("action", action.Type),
		zap.String("target", action.Target))

	switch action.Type {
	case "kill_process":
		// 通过命令通道下发 kill 命令
		return r.dispatcher.SendCommand(hostID, map[string]interface{}{
			"data_type": 9998, // 自动响应命令
			"data":      string(taskJSON),
		})
	case "quarantine_file":
		// 通过 scanner 插件下发隔离命令
		return r.dispatcher.SendCommand(hostID, map[string]interface{}{
			"data_type":   7003,
			"object_name": "scanner",
			"data":        string(taskJSON),
		})
	case "block_ip", "unblock_ip":
		// 通过命令通道下发 iptables/nftables 阻断命令
		return r.dispatcher.SendCommand(hostID, map[string]interface{}{
			"data_type": 9997, // 网络阻断命令
			"data":      string(taskJSON),
		})
	default:
		return fmt.Errorf("未知的响应动作: %s", action.Type)
	}
}
