package api

import (
	"errors"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// AdminTenantsHandler 平台超管租户管理 API。
//
// 路径: /api/v2/admin/tenants/*
// 鉴权: tenant.AdminMiddleware()  (必须 IsPlatformAdmin=true)
//
// 详见 docs/multi-tenant.md §4 + docs/api-reference.md
type AdminTenantsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewAdminTenantsHandler 构造租户管理 handler。
func NewAdminTenantsHandler(db *gorm.DB, logger *zap.Logger) *AdminTenantsHandler {
	return &AdminTenantsHandler{db: db, logger: logger}
}

// ListTenants GET /api/v2/admin/tenants
//
// 平台超管查看所有租户列表。普通用户被 AdminMiddleware 拦截。
func (h *AdminTenantsHandler) ListTenants(c *gin.Context) {
	var tenants []model.Tenant
	if err := h.db.Order("created_at DESC").Find(&tenants).Error; err != nil {
		h.logger.Error("列出租户失败", zap.Error(err))
		InternalError(c, "查询租户列表失败")
		return
	}
	Success(c, gin.H{
		"items": tenants,
		"total": len(tenants),
	})
}

// GetTenant GET /api/v2/admin/tenants/:id
func (h *AdminTenantsHandler) GetTenant(c *gin.Context) {
	id := c.Param("id")
	var t model.Tenant
	if err := h.db.Where("id = ?", id).First(&t).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			NotFound(c, "租户不存在")
			return
		}
		h.logger.Error("查询租户失败", zap.Error(err), zap.String("tenant_id", id))
		InternalError(c, "查询租户失败")
		return
	}
	Success(c, t)
}

// CreateTenantRequest POST /api/v2/admin/tenants 请求体。
type CreateTenantRequest struct {
	ID          string `json:"id" binding:"required,min=2,max=64"`
	Name        string `json:"name" binding:"required,min=1,max=255"`
	Type        string `json:"type" binding:"omitempty,oneof=standalone mssp_parent mssp_child internal"`
	ParentID    string `json:"parent_id"`
	DefaultMode string `json:"default_mode" binding:"omitempty,oneof=observe protect"`
	QuotaAgents int    `json:"quota_agents"`
}

// CreateTenant POST /api/v2/admin/tenants
//
// 创建新租户。仅平台超管可调用。
func (h *AdminTenantsHandler) CreateTenant(c *gin.Context) {
	var req CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误: "+err.Error())
		return
	}

	// 唯一性校验
	var existing model.Tenant
	if err := h.db.Where("id = ?", req.ID).First(&existing).Error; err == nil {
		BadRequest(c, "租户 ID 已存在")
		return
	}

	tenantType := req.Type
	if tenantType == "" {
		tenantType = string(model.TenantTypeStandalone)
	}
	defaultMode := req.DefaultMode
	if defaultMode == "" {
		defaultMode = string(model.TenantModeObserve)
	}
	quotaAgents := req.QuotaAgents
	if quotaAgents == 0 {
		quotaAgents = 100
	}

	t := model.Tenant{
		ID:                  req.ID,
		Name:                req.Name,
		Type:                model.TenantType(tenantType),
		Status:              model.TenantStatusActive,
		DefaultMode:         model.TenantMode(defaultMode),
		MLEnabled:           true,
		LLMEnabled:          false,
		QuotaAgents:         quotaAgents,
		QuotaLLMUSD:         100.00,
		QuotaEventsDay:      1000000000,
		RetentionAlertsDays: 90,
		RetentionEventsDays: 30,
		RetentionAuditDays:  180,
		IsolationStrategy:   model.IsolationShared,
	}
	if req.ParentID != "" {
		t.ParentID = &req.ParentID
	}

	if err := h.db.Create(&t).Error; err != nil {
		h.logger.Error("创建租户失败", zap.Error(err), zap.String("tenant_id", req.ID))
		InternalError(c, "创建租户失败")
		return
	}

	h.logger.Info("创建租户成功",
		zap.String("tenant_id", t.ID),
		zap.String("name", t.Name),
		zap.String("type", string(t.Type)),
	)
	Success(c, t)
}

// SuspendTenant POST /api/v2/admin/tenants/:id/suspend
//
// 暂停租户(行级软封禁,不删除数据)。
func (h *AdminTenantsHandler) SuspendTenant(c *gin.Context) {
	id := c.Param("id")
	if id == model.DefaultTenantID {
		BadRequest(c, "默认租户不可暂停")
		return
	}
	if err := h.db.Model(&model.Tenant{}).Where("id = ?", id).
		Update("status", model.TenantStatusSuspended).Error; err != nil {
		h.logger.Error("暂停租户失败", zap.Error(err), zap.String("tenant_id", id))
		InternalError(c, "暂停租户失败")
		return
	}
	SuccessMessage(c, "租户已暂停")
}

// ResumeTenant POST /api/v2/admin/tenants/:id/resume
func (h *AdminTenantsHandler) ResumeTenant(c *gin.Context) {
	id := c.Param("id")
	if err := h.db.Model(&model.Tenant{}).Where("id = ?", id).
		Update("status", model.TenantStatusActive).Error; err != nil {
		h.logger.Error("恢复租户失败", zap.Error(err), zap.String("tenant_id", id))
		InternalError(c, "恢复租户失败")
		return
	}
	SuccessMessage(c, "租户已恢复")
}
