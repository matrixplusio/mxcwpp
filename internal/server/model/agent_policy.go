package model

import (
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// AgentPolicy 是对全网 Agent 生效的运行时开关，存在 system_configs 里，在控制台修改，AgentCenter 定期读取。
//
// 这些开关一改就作用于全部主机，所以由数据库统一保存、改动经审计留痕，而不是散落在各节点的配置文件里：
// 配置文件由部署工具渲染，重新渲染会悄悄把手改的值覆盖回默认。
type AgentPolicy struct {
	// IdentityConflict 同一 AgentID 出现在不同机器上时：alert 只告警放行；reject 拒绝后来者，agent 自动换身份。
	IdentityConflict string `json:"identity_conflict"`
	// AutoUpdate 版本与「最新版本」不同的在线 agent 自动推送升级（全网同时，无灰度）。
	AutoUpdate bool `json:"auto_update"`
	// AutoPluginBroadcast 插件版本变化后自动向全部在线 agent 广播。
	AutoPluginBroadcast bool `json:"auto_plugin_broadcast"`
}

const (
	agentPolicyKey      = "agent_policy"
	agentPolicyCategory = "agent"

	IdentityConflictAlert  = "alert"
	IdentityConflictReject = "reject"
)

// Validate 检查取值合法。
func (p AgentPolicy) Validate() error {
	switch p.IdentityConflict {
	case IdentityConflictAlert, IdentityConflictReject:
		return nil
	default:
		return fmt.Errorf("identity_conflict 只能是 %s 或 %s", IdentityConflictAlert, IdentityConflictReject)
	}
}

// LoadAgentPolicy 读取已保存的策略；found=false 表示还从未保存过。
func LoadAgentPolicy(db *gorm.DB) (p AgentPolicy, found bool, err error) {
	var row SystemConfig
	err = db.Where("`key` = ? AND category = ?", agentPolicyKey, agentPolicyCategory).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AgentPolicy{}, false, nil
	}
	if err != nil {
		return AgentPolicy{}, false, err
	}
	if err := json.Unmarshal([]byte(row.Value), &p); err != nil {
		return AgentPolicy{}, true, fmt.Errorf("解析 agent 策略失败: %w", err)
	}
	return p, true, nil
}

// SaveAgentPolicy 校验后保存（不存在则创建）。
func SaveAgentPolicy(db *gorm.DB, p AgentPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	value, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var row SystemConfig
	err = db.Where("`key` = ? AND category = ?", agentPolicyKey, agentPolicyCategory).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return db.Create(&SystemConfig{
			Key:         agentPolicyKey,
			Category:    agentPolicyCategory,
			Value:       string(value),
			Description: "Agent 运行时策略（身份冲突处理、自动升级、插件自动广播）",
		}).Error
	}
	if err != nil {
		return err
	}
	return db.Model(&row).Update("value", string(value)).Error
}
