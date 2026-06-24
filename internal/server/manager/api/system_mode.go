package api

import (
	"errors"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
	"github.com/matrixplusio/mxcwpp/internal/server/common/tenant"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// SystemModeHandler 提供 /api/v2/system/mode 与 /api/v2/admin/tenants/:id/mode API。
//
// 设计文档: docs/operating-modes.md §5 切换流程
//
// 4 级覆盖优先级 (高 → 低): 规则级 > 主机标签级 > 租户级 > 全局默认。
// 本 handler 暂只暴露租户级 + 全局默认查询/切换,
// 主机标签级与规则级通过 baseline/rule API 改 (后续 PR)。
type SystemModeHandler struct {
	db       *gorm.DB
	logger   *zap.Logger
	resolver *mode.MemoryResolver
}

// NewSystemModeHandler 构造 mode handler。
func NewSystemModeHandler(db *gorm.DB, logger *zap.Logger, resolver *mode.MemoryResolver) *SystemModeHandler {
	return &SystemModeHandler{db: db, logger: logger, resolver: resolver}
}

// GetCurrentMode GET /api/v2/system/mode
//
// 返回当前生效的 mode 决策 (按当前 token 的 tenant)。
// 平台超管返回全局视图。
func (h *SystemModeHandler) GetCurrentMode(c *gin.Context) {
	id := tenant.GetIdentity(c)
	d := h.resolver.Resolve(mode.Scope{TenantID: id.ID})
	Success(c, gin.H{
		"mode":   string(d.Mode),
		"source": d.Source,
		"reason": d.Reason,
	})
}

// SetTenantModeRequest POST /api/v2/admin/tenants/:id/mode 请求体。
type SetTenantModeRequest struct {
	Mode string `json:"mode" binding:"required,oneof=observe protect"`
}

// SetTenantMode POST /api/v2/admin/tenants/:id/mode
//
// 仅平台超管可调用。租户级切换 → MemoryResolver + tenants 表持久化。
// protect 切换前应该做 6 门槛准入校验 (PR 留 hook,本 PR 暂仅记录 audit 警告)。
func (h *SystemModeHandler) SetTenantMode(c *gin.Context) {
	tenantID := c.Param("id")
	var req SetTenantModeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误: "+err.Error())
		return
	}
	newMode := mode.Mode(req.Mode)
	if !newMode.IsValid() {
		BadRequest(c, "无效的 mode 值")
		return
	}

	// 校验租户存在
	var t model.Tenant
	if err := h.db.Where("id = ?", tenantID).First(&t).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			NotFound(c, "租户不存在")
			return
		}
		h.logger.Error("查询租户失败", zap.String("tenant_id", tenantID), zap.Error(err))
		InternalError(c, "查询租户失败")
		return
	}

	// observe → protect 切换:记录 audit 警告 (6 门槛校验留后续 PR)
	if newMode == mode.Protect && t.DefaultMode != model.TenantModeProtect {
		h.logger.Warn("租户切到 protect 模式 (注: 6 门槛 G1-G6 准入校验留后续 PR)",
			zap.String("tenant_id", tenantID),
			zap.String("from", string(t.DefaultMode)),
			zap.String("to", string(newMode)),
		)
	}

	// 持久化
	t.DefaultMode = model.TenantMode(req.Mode)
	if err := h.db.Save(&t).Error; err != nil {
		h.logger.Error("保存租户 mode 失败",
			zap.String("tenant_id", tenantID),
			zap.Error(err))
		InternalError(c, "切换失败")
		return
	}

	// 更新内存 resolver
	if err := h.resolver.SetTenant(tenantID, newMode); err != nil {
		h.logger.Error("更新 resolver 失败", zap.Error(err))
	}

	h.logger.Info("租户 mode 切换成功",
		zap.String("tenant_id", tenantID),
		zap.String("mode", string(newMode)),
	)
	Success(c, gin.H{
		"tenant_id": tenantID,
		"mode":      string(newMode),
	})
}

// ListTenantModes GET /api/v2/admin/tenants/modes
//
// 列出所有租户的当前 mode 与 quota (仅平台超管)。
func (h *SystemModeHandler) ListTenantModes(c *gin.Context) {
	var tenants []model.Tenant
	if err := h.db.Order("created_at DESC").Find(&tenants).Error; err != nil {
		h.logger.Error("列出租户模式失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	items := make([]gin.H, 0, len(tenants))
	for _, t := range tenants {
		items = append(items, gin.H{
			"tenant_id":    t.ID,
			"tenant_name":  t.Name,
			"default_mode": string(t.DefaultMode),
			"status":       string(t.Status),
			"quota_agents": t.QuotaAgents,
			"ml_enabled":   t.MLEnabled,
			"llm_enabled":  t.LLMEnabled,
		})
	}
	Success(c, gin.H{"items": items, "total": len(items)})
}
