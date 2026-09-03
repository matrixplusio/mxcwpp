package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"go.uber.org/zap"
)

// PrivilegeStage 处理 Agent 上报的 privilege escalation 事件 (P1-3).
//
// DataType 3005 (内核态提权 hook 上报):
//
//	30 commit_creds  — UID/GID/cap 切换
//	31 setuid        — setreuid/setresuid
//	32 setgid        — setregid/setresgid
//	33 ptrace        — ptrace 注入 (T1055.008)
//	34 mount         — mount 调用 (T1611 容器逃逸)
//	35 kmod_load     — LKM rootkit 加载 (T1547.006)
//
// 规则:
//   - UID 0→0 + cap 提升 → high
//   - 非 root 提到 root → critical
//   - ptrace 跨进程 → high
//   - mount 含 /proc/self/exe 或 cgroup → critical (容器逃逸)
//   - kmod_load 命中 已知 rootkit 名 → critical
type PrivilegeStage struct {
	logger *zap.Logger
	// 已知 rootkit 模块名 (lowercase)
	knownRootkitMods map[string]struct{}
}

// NewPrivilegeStage 构造.
func NewPrivilegeStage(logger *zap.Logger) *PrivilegeStage {
	if logger == nil {
		logger = zap.NewNop()
	}
	known := make(map[string]struct{}, 12)
	for _, name := range []string{
		"diamorphine", "reptile", "beurk", "suterusu", "adore-ng", "adore",
		"knark", "phalanx", "kbeast", "mood-nt", "wnps", "evilbpf",
	} {
		known[name] = struct{}{}
	}
	return &PrivilegeStage{logger: logger, knownRootkitMods: known}
}

// Name 满足 Stage interface.
func (s *PrivilegeStage) Name() string { return "privilege_escalation" }

// Process 处理 DataType 3005 事件。
func (s *PrivilegeStage) Process(_ context.Context, ev PipelineEvent) ([]Alert, error) {
	if ev.DataType != 3005 {
		return nil, nil
	}
	fields, err := ev.Fields()
	if err != nil {
		return nil, nil
	}
	eventType, _ := strconv.Atoi(fields["event_type"])
	if eventType == 0 {
		return nil, nil
	}
	oldUID, _ := strconv.Atoi(fields["old_uid"])
	newUID, _ := strconv.Atoi(fields["new_uid"])
	comm := fields["comm"]

	severity := "medium"
	rule := "PRIV_GENERIC"
	tactic := "TA0004" // Privilege Escalation
	technique := "T1548"
	detail := ""

	switch eventType {
	case 30: // commit_creds
		if oldUID != 0 && newUID == 0 {
			severity = "critical"
			rule = "PRIV_UID0_GAIN"
			detail = fmt.Sprintf("non-root (uid=%d) 提到 root, comm=%s", oldUID, comm)
		} else if oldUID == 0 && newUID == 0 {
			// 仅当 cap_effective 变化才告警 (高频, 否则噪声)
			capEff, _ := strconv.ParseUint(fields["cap_effective"], 16, 64)
			if capEff != 0 {
				severity = "high"
				rule = "PRIV_CAP_GAIN"
				detail = fmt.Sprintf("root cap 变更, cap_effective=0x%x", capEff)
			} else {
				return nil, nil
			}
		} else {
			severity = "low"
			rule = "PRIV_UID_CHANGE"
			detail = fmt.Sprintf("uid %d → %d", oldUID, newUID)
		}
	case 31, 32: // setuid/setgid
		if newUID == 0 || newUID == -1 {
			severity = "high"
			rule = "PRIV_SETUID_ROOT"
			detail = fmt.Sprintf("setuid/setgid → 0/-1, comm=%s", comm)
		} else {
			return nil, nil
		}
	case 33: // ptrace
		targetPID := fields["target_pid"]
		severity = "high"
		rule = "PRIV_PTRACE"
		tactic = "TA0005" // Defense Evasion
		technique = "T1055.008"
		detail = fmt.Sprintf("ptrace 注入 target_pid=%s comm=%s", targetPID, comm)
	case 34: // mount
		payload := fields["payload"]
		severity = "high"
		rule = "PRIV_MOUNT"
		tactic = "TA0004"
		technique = "T1611"
		if containsAny(payload, "/proc/self/exe", "/sys/fs/cgroup", "/dev/shm", "//") {
			severity = "critical"
			rule = "PRIV_MOUNT_ESCAPE"
		}
		detail = fmt.Sprintf("mount payload=%s comm=%s", trunc(payload, 128), comm)
	case 35: // kmod_load
		modName := fields["payload"]
		severity = "high"
		rule = "PRIV_KMOD_LOAD"
		tactic = "TA0003" // Persistence
		technique = "T1547.006"
		if _, hit := s.knownRootkitMods[lowerStr(modName)]; hit {
			severity = "critical"
			rule = "PRIV_KMOD_ROOTKIT"
		}
		detail = fmt.Sprintf("kmod_load name=%s comm=%s", modName, comm)
	}

	payload, _ := json.Marshal(map[string]any{
		"event_type":    eventType,
		"pid":           fields["pid"],
		"ppid":          fields["ppid"],
		"old_uid":       oldUID,
		"new_uid":       newUID,
		"target_pid":    fields["target_pid"],
		"cap_effective": fields["cap_effective"],
		"comm":          comm,
		"data":          fields["payload"],
		"rule":          rule,
		"detail":        detail,
		"would_action":  map[string]any{"type": "alert_only"},
	})

	return []Alert{{
		AlertID:        fmt.Sprintf("alrt-priv-%s-%d-%d", ev.HostID, ev.Partition, ev.Offset),
		RuleID:         rule,
		Severity:       severity,
		ATTCKTactic:    tactic,
		ATTCKTechnique: technique,
		Payload:        payload,
		WouldAction:    payload,
	}}, nil
}

var _ Stage = (*PrivilegeStage)(nil)

// containsAny 任一 substring 命中。
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func lowerStr(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
