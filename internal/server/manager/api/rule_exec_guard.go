package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/audit"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// guardCustomExecRule 拦截自定义规则携带可执行内容的写入。
//
// command_exec 的参数与 fix.command 都会以 root 在全部目标主机上执行，所以放开自定义
// 规则的这两个字段，等于把"基线配置权限"提权成"全舰队任意代码执行"。这条闸门只作用于
// 写入路径：内置规则（随发布同步、builtin=true）不受限，存量规则也不受影响——本次收敛的
// 是提权路径本身，不是回溯清理既有资产。
//
// allowCustomExec 为 true 时（server.security.allow_custom_exec_rules）放行，供确有
// 自定义可执行规则需求的环境显式启用。
func guardCustomExecRule(allowCustomExec, builtin bool, check model.CheckConfig, fix model.FixConfig) error {
	if allowCustomExec || builtin {
		return nil
	}
	var offending []string
	if check.HasCommandExecCheck() {
		offending = append(offending, "check_config 含 command_exec 检查")
	}
	if fix.HasFixCommand() {
		offending = append(offending, "fix_config.command 含修复命令")
	}
	if len(offending) == 0 {
		return nil
	}
	return fmt.Errorf(
		"自定义规则不允许携带在主机上执行的命令（%s）。这些内容会以 root 在全部目标主机执行；"+
			"如确需此能力，请由管理员开启 server.security.allow_custom_exec_rules",
		strings.Join(offending, "；"))
}

// guardImportedPolicy 对导入的策略逐条规则套用同一把闸门。
// 导入的规则一律落为自定义规则（builtin=false），因此与逐条创建走同样的判定。
func guardImportedPolicy(allowCustomExec bool, policy *PolicyExportFormat) error {
	if allowCustomExec {
		return nil
	}
	for _, rule := range policy.Rules {
		var check model.CheckConfig
		var fix model.FixConfig
		// Check/Fix 是 map[string]any，转换失败按"无法确认内容安全"处理，不静默放行。
		if b, err := json.Marshal(rule.Check); err == nil {
			if err := json.Unmarshal(b, &check); err != nil {
				return fmt.Errorf("规则 %s 的 check 配置无法解析，拒绝导入: %w", rule.RuleID, err)
			}
		}
		if b, err := json.Marshal(rule.Fix); err == nil {
			if err := json.Unmarshal(b, &fix); err != nil {
				return fmt.Errorf("规则 %s 的 fix 配置无法解析，拒绝导入: %w", rule.RuleID, err)
			}
		}
		if err := guardCustomExecRule(allowCustomExec, false, check, fix); err != nil {
			return fmt.Errorf("策略 %s 的规则 %s：%w", policy.ID, rule.RuleID, err)
		}
	}
	return nil
}

// CustomExecRuleItem 是一条"自定义且携带可执行内容"的基线规则。
type CustomExecRuleItem struct {
	PolicyID       string `json:"policy_id"`
	PolicyName     string `json:"policy_name"`
	RuleID         string `json:"rule_id"`
	Title          string `json:"title"`
	Enabled        bool   `json:"enabled"`
	HasCommandExec bool   `json:"has_command_exec"`
	HasFixCommand  bool   `json:"has_fix_command"`
	// FixCommand 截断展示，供人工研判；完整内容在规则详情里看。
	FixCommand string `json:"fix_command,omitempty"`
	UpdatedAt  string `json:"updated_at"`
}

// ListCustomExecRules 列出所有自定义（非内置）且携带可执行内容的基线规则。
// GET /api/v1/policies/custom-exec-rules
//
// 写入路径已禁止新增这类规则，但存量规则仍会以 root 在目标主机执行。本接口给出
// 完整清单供人工研判：确认无用的直接停用/删除，确需保留的再决定是否开启
// server.security.allow_custom_exec_rules。没有这份清单就无法判断收紧到什么程度是安全的。
func (h *RulesHandler) ListCustomExecRules(c *gin.Context) {
	var rules []model.Rule
	if err := h.db.Where("builtin = ?", false).Find(&rules).Error; err != nil {
		h.logger.Error("查询自定义规则失败", zap.Error(err))
		InternalError(c, "查询自定义规则失败")
		return
	}

	policyNames := map[string]string{}
	var policies []model.Policy
	if err := h.db.Select("id", "name").Find(&policies).Error; err == nil {
		for _, p := range policies {
			policyNames[p.ID] = p.Name
		}
	}

	items := make([]CustomExecRuleItem, 0)
	for _, r := range rules {
		hasCheck := r.CheckConfig.HasCommandExecCheck()
		hasFix := r.FixConfig.HasFixCommand()
		if !hasCheck && !hasFix {
			continue
		}
		cmd := strings.TrimSpace(r.FixConfig.Command)
		if len(cmd) > 200 {
			cmd = cmd[:200] + "..."
		}
		items = append(items, CustomExecRuleItem{
			PolicyID:       r.PolicyID,
			PolicyName:     policyNames[r.PolicyID],
			RuleID:         r.RuleID,
			Title:          r.Title,
			Enabled:        r.Enabled,
			HasCommandExec: hasCheck,
			HasFixCommand:  hasFix,
			FixCommand:     cmd,
			UpdatedAt:      r.UpdatedAt.String(),
		})
	}

	h.logger.Info("[AUDIT] 查询自定义可执行基线规则清单",
		zap.String("actor", c.GetString("username")),
		zap.Int("total", len(items)))

	Success(c, gin.H{
		"total": len(items),
		"items": items,
		"note":  "这些规则的内容会以 root 在目标主机执行。写入路径已禁止新增；存量规则请逐条研判后停用或保留。",
	})
}

// auditExecRuleRejected 把"携带可执行内容的自定义规则被拒"记入平台审计流。
//
// 这类拒绝是安全事件：它意味着有人尝试写入会在全舰队以 root 执行的内容。只落 zap 日志
// 等于没有记录——运维看不到、查不到、也无法据此复盘。故与 access.denied 同级进审计。
func auditExecRuleRejected(c *gin.Context, action, resourceID, detail string) {
	audit.Record(c.Request.Context(), audit.Event{
		ActorType:    model.ActorTypeUser,
		Username:     c.GetString("username"),
		Action:       action,
		Outcome:      model.OutcomeFailure,
		ResourceType: "baseline_rule",
		ResourceID:   resourceID,
		Path:         c.Request.URL.Path,
		IP:           c.ClientIP(),
		StatusCode:   http.StatusBadRequest,
		Detail:       detail,
	})
}
