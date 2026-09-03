// Package handler 给 manager HTTP 注册 GraphQL endpoint (P4-7).
package handler

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/api"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/graphql"
)

// GraphQLHandler 处理 POST /api/v2/graphql.
type GraphQLHandler struct {
	registry *graphql.Registry
	logger   *zap.Logger
}

// NewGraphQLHandler 构造.
func NewGraphQLHandler(reg *graphql.Registry, logger *zap.Logger) *GraphQLHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &GraphQLHandler{registry: reg, logger: logger}
}

// Handle 入口.
//
// 入参 JSON 形式:
//
//	{
//	  "operation": "alerts",
//	  "variables": {"severity": "critical", "limit": 20}
//	}
//
// 出参 GraphQL 风格 {data, errors}.
func (h *GraphQLHandler) Handle(c *gin.Context) {
	var req graphql.Request
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid json: "+err.Error())
		return
	}
	if tenantID, ok := c.Get("tenant_id"); ok {
		if s, ok2 := tenantID.(string); ok2 {
			req.TenantID = s
		}
	}
	resp := h.registry.Execute(c.Request.Context(), &req)
	c.JSON(200, resp)
}
