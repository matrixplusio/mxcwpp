package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// RemediationHandler 漏洞修复 API 处理器
type RemediationHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewRemediationHandler 创建修复处理器
func NewRemediationHandler(db *gorm.DB, logger *zap.Logger) *RemediationHandler {
	return &RemediationHandler{db: db, logger: logger}
}

// GetAdvice 获取漏洞修复建议
// GET /api/v1/vulnerabilities/:id/advice
func (h *RemediationHandler) GetAdvice(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的漏洞 ID")
		return
	}

	var vuln model.Vulnerability
	if err := h.db.First(&vuln, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "漏洞不存在")
			return
		}
		h.logger.Error("查询漏洞失败", zap.Error(err))
		InternalError(c, "查询漏洞失败")
		return
	}

	svc := biz.NewRemediationService(h.db, h.logger)
	advice := svc.GetAdvice(&vuln)
	Success(c, advice)
}

// PatchVulnerability 标记漏洞已修复
// POST /api/v1/vulnerabilities/:id/patch
func (h *RemediationHandler) PatchVulnerability(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的漏洞 ID")
		return
	}

	var vuln model.Vulnerability
	if err := h.db.First(&vuln, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "漏洞不存在")
			return
		}
		h.logger.Error("查询漏洞失败", zap.Error(err))
		InternalError(c, "查询漏洞失败")
		return
	}

	if vuln.Status == "patched" {
		BadRequest(c, "漏洞已修复，无需重复操作")
		return
	}

	var req struct {
		HostIDs []string `json:"hostIds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// body 为空时也允许，表示全部标记
		req.HostIDs = nil
	}

	svc := biz.NewRemediationService(h.db, h.logger)
	if err := svc.PatchVulnerability(uint(id), req.HostIDs); err != nil {
		h.logger.Error("标记漏洞修复失败", zap.Uint64("id", id), zap.Error(err))
		InternalError(c, "标记修复失败")
		return
	}

	SuccessMessage(c, "漏洞已标记为修复")
}

// GetRemediationStats 获取修复统计概览
// GET /api/v1/vulnerabilities/stats/remediation
func (h *RemediationHandler) GetRemediationStats(c *gin.Context) {
	svc := biz.NewRemediationService(h.db, h.logger)
	stats, err := svc.GetRemediationStats()
	if err != nil {
		h.logger.Error("获取修复统计失败", zap.Error(err))
		InternalError(c, "获取修复统计失败")
		return
	}
	Success(c, stats)
}

// GetRemediationTrend 获取修复趋势
// GET /api/v1/vulnerabilities/stats/trend
func (h *RemediationHandler) GetRemediationTrend(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days <= 0 || days > 365 {
		days = 30
	}

	svc := biz.NewRemediationService(h.db, h.logger)
	trend, err := svc.GetRemediationTrend(days)
	if err != nil {
		h.logger.Error("获取修复趋势失败", zap.Error(err))
		InternalError(c, "获取修复趋势失败")
		return
	}
	Success(c, trend)
}

// VerifyRemediation 验证漏洞修复（比对主机当前版本）
// POST /api/v1/vulnerabilities/:id/verify
func (h *RemediationHandler) VerifyRemediation(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的漏洞 ID")
		return
	}

	var req struct {
		HostID string `json:"hostId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "无效的请求参数")
		return
	}

	verifier := biz.NewRemediationVerifier(h.db, h.logger)

	if req.HostID != "" {
		// 验证单个主机
		result, err := verifier.VerifyHost(uint(id), req.HostID)
		if err != nil {
			h.logger.Error("验证修复失败", zap.Error(err))
			InternalError(c, "验证修复失败")
			return
		}
		Success(c, result)
	} else {
		// 批量验证所有受影响主机
		results, err := verifier.BatchVerify(uint(id))
		if err != nil {
			h.logger.Error("批量验证修复失败", zap.Error(err))
			InternalError(c, "验证失败")
			return
		}
		Success(c, results)
	}
}

// VerifyTask 验证修复任务的结果
// POST /api/v1/remediation-tasks/:id/verify
func (h *RemediationHandler) VerifyTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	verifier := biz.NewRemediationVerifier(h.db, h.logger)
	result, err := verifier.VerifyTask(uint(id))
	if err != nil {
		BadRequest(c, "请求参数错误")
		return
	}
	Success(c, result)
}
