package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/common/mode"
	"github.com/matrixplusio/mxcwpp/internal/server/common/tenant"
)

// SystemModeHandler 提供 /api/v2/system/mode 查询 API。
//
// 设计文档: docs/operating-modes.md §5 切换流程
//
// 单租户收敛后按租户切换模式的接口已移除：模式是部署级设置，不再逐租户区分。
// 覆盖优先级 (高 → 低): 规则级 > 主机标签级 > 部署默认；
// 前两级通过 baseline/rule API 调整。
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
// 返回当前生效的 mode 决策。
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
