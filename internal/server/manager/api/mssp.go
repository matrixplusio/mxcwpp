// Package api — MSSP 控制台 HTTP 路由 (A3 审计修复, 对齐 UI api/mssp.ts).
//
// Endpoints (全部走 /api/v2/mssp/):
//
//	GET    /dashboard                  控制台汇总
//	GET    /child-tenants              子租户列表
//	POST   /child-tenants              新建子租户
//	GET    /child-tenants/:id          详情
//	POST   /child-tenants/:id/suspend  暂停
//	POST   /child-tenants/:id/resume   恢复
//	GET    /alerts                     横跨子租户告警
//
// 严格走 response.go 信封, 不直接 c.JSON.
package api

import (
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz/mssp"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// MSSPHandler 多租户托管 console.
type MSSPHandler struct {
	svc    *mssp.Service
	logger *zap.Logger
}

// NewMSSPHandler 构造.
func NewMSSPHandler(svc *mssp.Service, logger *zap.Logger) *MSSPHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &MSSPHandler{svc: svc, logger: logger}
}

// parentTenantID 从 JWT 提取调用者租户; 暂未接入 JWT middleware 时回退 t-default.
func parentTenantID(c *gin.Context) string {
	if v, ok := c.Get("tenant_id"); ok {
		if s, ok2 := v.(string); ok2 && s != "" {
			return s
		}
	}
	return "t-default"
}

// Dashboard GET /mssp/dashboard.
func (h *MSSPHandler) Dashboard(c *gin.Context) {
	ctx := c.Request.Context()
	parent := parentTenantID(c)
	children, err := h.svc.ListChildren(ctx, parent)
	if err != nil {
		InternalError(c, "list children failed: "+err.Error())
		return
	}
	var active, totalHosts, criticalAlerts int64
	for _, ch := range children {
		if ch.Status == "active" {
			active++
		}
		totalHosts += ch.UsedAgents
		criticalAlerts += ch.CriticalAlerts
	}
	Success(c, gin.H{
		"total_child_tenants":    len(children),
		"active_child_tenants":   active,
		"total_hosts_managed":    totalHosts,
		"critical_alerts_7d":     criticalAlerts,
		"pending_quota_requests": 0,
	})
}

// ListChildTenants GET /mssp/child-tenants.
func (h *MSSPHandler) ListChildTenants(c *gin.Context) {
	ctx := c.Request.Context()
	parent := parentTenantID(c)
	children, err := h.svc.ListChildren(ctx, parent)
	if err != nil {
		InternalError(c, err.Error())
		return
	}
	// 服务端过滤 status / search
	status := strings.TrimSpace(c.Query("status"))
	search := strings.ToLower(strings.TrimSpace(c.Query("search")))
	filtered := make([]mssp.ChildTenant, 0, len(children))
	for _, ch := range children {
		if status != "" && ch.Status != status {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(ch.Name+ch.ID), search) {
			continue
		}
		filtered = append(filtered, ch)
	}
	Success(c, gin.H{"items": filtered, "total": len(filtered)})
}

// GetChildTenant GET /mssp/child-tenants/:id.
func (h *MSSPHandler) GetChildTenant(c *gin.Context) {
	ctx := c.Request.Context()
	parent := parentTenantID(c)
	id := c.Param("id")
	children, err := h.svc.ListChildren(ctx, parent)
	if err != nil {
		InternalError(c, err.Error())
		return
	}
	for _, ch := range children {
		if ch.ID == id {
			Success(c, ch)
			return
		}
	}
	NotFound(c, "child tenant not found: "+id)
}

// CreateChildTenant POST /mssp/child-tenants.
func (h *MSSPHandler) CreateChildTenant(c *gin.Context) {
	var req struct {
		ID           string `json:"id" binding:"required"`
		Name         string `json:"name" binding:"required"`
		ContactEmail string `json:"contact_email"`
		HostQuota    int64  `json:"host_quota"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid json: "+err.Error())
		return
	}
	parent := parentTenantID(c)
	pid := parent
	child := model.Tenant{
		ID:          req.ID,
		Name:        req.Name,
		ParentID:    &pid,
		Status:      "active",
		QuotaAgents: int(req.HostQuota),
	}
	if err := h.svc.CreateChildTenant(c.Request.Context(), parent, child); err != nil {
		BadRequest(c, "create failed: "+err.Error())
		return
	}
	Success(c, child)
}

// SuspendChildTenant POST /mssp/child-tenants/:id/suspend.
func (h *MSSPHandler) SuspendChildTenant(c *gin.Context) {
	id := c.Param("id")
	if err := h.setChildStatus(c, id, "suspended"); err != nil {
		InternalError(c, err.Error())
		return
	}
	SuccessMessage(c, "suspended")
}

// ResumeChildTenant POST /mssp/child-tenants/:id/resume.
func (h *MSSPHandler) ResumeChildTenant(c *gin.Context) {
	id := c.Param("id")
	if err := h.setChildStatus(c, id, "active"); err != nil {
		InternalError(c, err.Error())
		return
	}
	SuccessMessage(c, "resumed")
}

// setChildStatus 直更 tenant status (校验是子租户).
func (h *MSSPHandler) setChildStatus(c *gin.Context, childID, status string) error {
	parent := parentTenantID(c)
	return h.svc.UpdateChildStatus(c.Request.Context(), parent, childID, status)
}

// CrossTenantAlerts GET /mssp/alerts.
func (h *MSSPHandler) CrossTenantAlerts(c *gin.Context) {
	ctx := c.Request.Context()
	groupBy := c.DefaultQuery("group_by", "tenant_id")
	counts, err := h.svc.AggregateAlerts(ctx, parentTenantID(c), groupBy)
	if err != nil {
		InternalError(c, err.Error())
		return
	}
	Success(c, gin.H{"items": counts, "total": len(counts)})
}
