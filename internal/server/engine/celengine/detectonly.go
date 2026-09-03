package celengine

import (
	"time"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// detect-only 上线观察期（P3，对齐 CWPP detect-only 基线）：
//
// 新增自定义规则 / 新上线主机有一段观察期，期内 CEL 命中只降级为 indicator（不独立告警），
// 给环境留出调 exception / 建基线的窗口，避免新规则、新机上线初期刷屏（重演 P1 误报）。
// 事件仍走 anomaly/storyline 关联（与低保真 indicator 同语义），只少告警不漏存。
const (
	// ruleGraceWindow 用户新增非内置规则的上线观察期。内置规则随产品验证，不设观察期。
	ruleGraceWindow = 72 * time.Hour
	// hostGraceWindow 新主机上线观察期（基于 hosts.created_at 首见时间）。
	hostGraceWindow = 48 * time.Hour
)

// graceDecision 判断本次命中是否处于观察期，处于则降级 indicator 不告警。
// 返回命中的维度（rule/host）仅用于日志。不查 DB —— 主机观察期由调用方一次性预算好传入。
//
// 豁免：critical 规则不受任何观察期约束 —— 反弹 shell / C2 等真威胁不等观察期。
func graceDecision(rule *model.DetectionRule, hostGraced bool, now time.Time) (bool, string) {
	if rule.Severity == "critical" {
		return false, ""
	}
	// 规则维度：仅用户新增的非内置规则，上线 ruleGraceWindow 内。
	if !rule.Builtin && rule.EffectiveAt != nil && !rule.EffectiveAt.IsZero() &&
		now.Sub(rule.EffectiveAt.Time()) < ruleGraceWindow {
		return true, "rule"
	}
	// 主机维度：新上线主机 hostGraceWindow 内，对所有非 critical 规则生效。
	if hostGraced {
		return true, "host"
	}
	return false, ""
}

// hostInGrace 主机是否处于上线观察期，基于 hosts.created_at 首见时间。
// 用 created_at 而非 agent_start_time：后者每次 agent 重启都会重置，会让主机反复进窗。
//
// 读 hostCreatedAt 原子快照（每 5min 全量刷新，见 host_grace.go），热路径零 DB 零锁。
// 快照未就绪 / 查不到（新主机尚未进快照）/ 零值，按"非观察期"处理（不误抑制；新主机至多
// 5min 后进窗，相对 48h 窗口可忽略）。原实现每事件查一次 DB，高事件量打满 MySQL 致 engine
// CPU 飙高，已废弃。
func (g *AlertGenerator) hostInGrace(hostID string, now time.Time) bool {
	snap := g.hostCreatedAt.Load()
	if snap == nil {
		return false
	}
	created, ok := (*snap)[hostID]
	if !ok || created.IsZero() {
		return false
	}
	return now.Sub(created) < hostGraceWindow
}
