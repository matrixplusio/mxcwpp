package transfer

import (
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/common/agentident"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/metrics"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const identityConflictReject = "reject"

// PolicySource 提供控制台设置的 agent 运行时策略。
type PolicySource interface {
	Get() model.AgentPolicy
}

// SetPolicy 注入运行时策略；未注入时按配置文件（测试与早期启动路径）。
func (s *Service) SetPolicy(p PolicySource) { s.policy = p }

func (s *Service) identityConflictMode() string {
	if s.policy != nil {
		return s.policy.Get().IdentityConflict
	}
	return s.cfg.MTLS.IdentityConflict
}

// checkIdentity 判断这条连接的 AgentID 是否已被另一台机器占用，返回冲突说明，不冲突时为空。
//
// AgentID 在 agent 本地派生，从同一镜像克隆出的机器会算出同一个 ID；客户端证书被拷到别的机器上
// 也是同一表现。本地无从察觉，只能在这里比对：
//   - 指纹：该 AgentID 首次接入时记下的机器指纹与本次不同；
//   - 在线连接：同一 AgentID 正在线，而对方是另一台机器（指纹不同；旧版 agent 不报指纹时比主机名）。
//
// 同一台机器断线重连时指纹相同，不算冲突。
func (s *Service) checkIdentity(agentID, fingerprint, hostname string) string {
	if fingerprint != "" {
		var stored string
		s.db.Model(&model.Host{}).Where("host_id = ?", agentID).Pluck("machine_fingerprint", &stored)
		if stored != "" && stored != fingerprint {
			return "该 AgentID 已绑定另一台机器（机器指纹不同）"
		}
	}

	s.connMu.RLock()
	live := s.connections[agentID]
	s.connMu.RUnlock()
	if live == nil {
		return ""
	}
	if fingerprint != "" && live.Fingerprint != "" {
		if live.Fingerprint != fingerprint {
			return fmt.Sprintf("该 AgentID 正被主机 %s 使用（机器指纹不同）", live.GetHostname())
		}
		return ""
	}
	if other := live.GetHostname(); other != "" && hostname != "" && other != hostname {
		return fmt.Sprintf("该 AgentID 正被主机 %s 使用", other)
	}
	return ""
}

// handleIdentityConflict 记录冲突并按配置决定放行还是拒绝。返回非 nil 时调用方应以此结束连接。
func (s *Service) handleIdentityConflict(agentID, hostname, detail string) error {
	action := "alert"
	if s.identityConflictMode() == identityConflictReject {
		action = identityConflictReject
	}
	metrics.IncIdentityConflict(action)
	s.logger.Warn("Agent 身份冲突",
		zap.String("agent_id", agentID),
		zap.String("hostname", hostname),
		zap.String("detail", detail),
		zap.String("action", action),
	)
	go s.raiseIdentityConflictAlert(agentID, hostname, detail)

	if action == identityConflictReject {
		return agentident.ConflictError(detail)
	}
	return nil
}

// raiseIdentityConflictAlert 每个 AgentID 一组告警：未处理前重复冲突只累加命中。
func (s *Service) raiseIdentityConflictAlert(agentID, hostname, detail string) {
	now := model.Now()
	_, err := model.UpsertGroupedAlert(s.db, "identity-conflict-"+agentID, func() model.Alert {
		return model.Alert{
			HostID:      agentID,
			RuleID:      "agent_identity_conflict",
			Source:      model.AlertSourceAgent,
			Severity:    "high",
			Category:    "agent_identity_conflict",
			Title:       fmt.Sprintf("Agent 身份冲突: %s", hostname),
			Description: fmt.Sprintf("主机 %s 以 AgentID %s 接入，但%s。常见原因是从同一镜像克隆的机器，或客户端证书被拷贝到了别的机器上。", hostname, agentID, detail),
			Status:      model.AlertStatusActive,
			FirstSeenAt: now,
			LastSeenAt:  now,
			HitCount:    1,
		}
	}, func(existing *model.Alert) error {
		return s.db.Model(existing).Updates(map[string]any{
			"last_seen_at": now,
			"hit_count":    gorm.Expr("hit_count + 1"),
		}).Error
	})
	if err != nil {
		s.logger.Warn("记录 Agent 身份冲突告警失败", zap.String("agent_id", agentID), zap.Error(err))
	}
}

// recordFingerprint 首次见到带指纹的连接时补记主机的指纹基线；已有基线不覆盖。
func (s *Service) recordFingerprint(conn *Connection) {
	if conn.Fingerprint == "" {
		return
	}
	conn.fingerprintOnce.Do(func() {
		err := s.db.Model(&model.Host{}).
			Where("host_id = ? AND (machine_fingerprint IS NULL OR machine_fingerprint = '')", conn.AgentID).
			Update("machine_fingerprint", conn.Fingerprint).Error
		if err != nil {
			s.logger.Warn("记录主机指纹失败", zap.String("agent_id", conn.AgentID), zap.Error(err))
		}
	})
}
