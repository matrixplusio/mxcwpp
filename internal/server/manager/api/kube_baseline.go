package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// KubeBaselineHandler 基线检查 API Handler
type KubeBaselineHandler struct {
	db      *gorm.DB
	logger  *zap.Logger
	checker *biz.KubeBaselineChecker
}

// NewKubeBaselineHandler 创建基线检查 Handler
func NewKubeBaselineHandler(db *gorm.DB, logger *zap.Logger, checker *biz.KubeBaselineChecker) *KubeBaselineHandler {
	return &KubeBaselineHandler{db: db, logger: logger, checker: checker}
}

// ListBaseline 基线检查列表（含统计）
func (h *KubeBaselineHandler) ListBaseline(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	search := c.Query("search")
	clusterID := c.Query("cluster_id")
	category := c.Query("category")
	result := c.Query("result")

	query := h.db.Model(&model.KubeBaseline{})

	if search != "" {
		query = query.Where("title LIKE ? OR check_name LIKE ? OR check_id LIKE ?", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}
	if clusterID != "" {
		query = query.Where("cluster_id = ?", clusterID)
	}
	if category != "" {
		query = query.Where("category = ?", category)
	}
	if result != "" {
		query = query.Where("result = ?", result)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询基线检查总数失败", zap.Error(err))
		InternalError(c, "查询基线检查列表失败")
		return
	}

	var checks []model.KubeBaseline
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("checked_at DESC").Find(&checks).Error; err != nil {
		h.logger.Error("查询基线检查列表失败", zap.Error(err))
		InternalError(c, "查询基线检查列表失败")
		return
	}

	// 统计信息（单次聚合查询替代 3 条独立 COUNT）
	var statsResult struct {
		TotalChecks int64 `gorm:"column:total_checks"`
		Passed      int64 `gorm:"column:passed"`
		Failed      int64 `gorm:"column:failed"`
	}
	statsQuery := h.db.Model(&model.KubeBaseline{})
	if clusterID != "" {
		statsQuery = statsQuery.Where("cluster_id = ?", clusterID)
	}
	statsQuery.Select(`
		COUNT(*) AS total_checks,
		SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END) AS passed,
		SUM(CASE WHEN result = 'fail' THEN 1 ELSE 0 END) AS failed
	`).Scan(&statsResult)

	totalChecks := statsResult.TotalChecks
	passed := statsResult.Passed
	failed := statsResult.Failed

	var passRate float64
	if passed+failed > 0 {
		passRate = float64(passed) / float64(passed+failed) * 100
	}

	Success(c, gin.H{
		"items": checks,
		"total": total,
		"stats": gin.H{
			"passRate":    int(passRate),
			"totalChecks": totalChecks,
			"passed":      passed,
			"failed":      failed,
		},
	})
}

// GetBaselineDetail 基线检查项详情
func (h *KubeBaselineHandler) GetBaselineDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的 ID")
		return
	}

	var check model.KubeBaseline
	if err := h.db.First(&check, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "检查项不存在")
			return
		}
		h.logger.Error("查询检查项失败", zap.Error(err))
		InternalError(c, "查询检查项失败")
		return
	}

	Success(c, check)
}

// RunBaselineCheck 执行基线检查
func (h *KubeBaselineHandler) RunBaselineCheck(c *gin.Context) {
	var req struct {
		ClusterID *uint `json:"cluster_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误: cluster_id 必填")
		return
	}

	results, err := h.checker.RunChecks(*req.ClusterID)
	if err != nil {
		h.logger.Error("执行基线检查失败", zap.Error(err))
		InternalError(c, "内部服务错误")
		return
	}

	passed := 0
	for _, r := range results {
		if r.Result == "pass" {
			passed++
		}
	}

	Success(c, gin.H{
		"total":    len(results),
		"passed":   passed,
		"failed":   len(results) - passed,
		"passRate": passed * 100 / max(len(results), 1),
		"items":    results,
	})
}
