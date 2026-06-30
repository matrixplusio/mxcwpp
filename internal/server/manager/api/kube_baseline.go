package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
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

// ListBaselineTasks 基线检查任务列表（任务为指向：每次检测=一个任务）
func (h *KubeBaselineHandler) ListBaselineTasks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	clusterID := c.Query("cluster_id")

	query := h.db.Model(&model.KubeBaselineTask{})
	if clusterID != "" {
		query = query.Where("cluster_id = ?", clusterID)
	}

	var total int64
	query.Count(&total)

	var tasks []model.KubeBaselineTask
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("id DESC").Find(&tasks).Error; err != nil {
		h.logger.Error("查询基线任务列表失败", zap.Error(err))
		InternalError(c, "查询基线任务列表失败")
		return
	}

	SuccessPaginated(c, total, tasks)
}

// GetBaselineTrend 合规趋势：返回某集群最近 N 次完成任务的通过率/加权分时间序列（用于趋势图）
func (h *KubeBaselineHandler) GetBaselineTrend(c *gin.Context) {
	clusterID := c.Query("cluster_id")
	if clusterID == "" {
		BadRequest(c, "cluster_id 必填")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "30"))
	if limit <= 0 || limit > 365 {
		limit = 30
	}

	type trendPoint struct {
		TaskID        uint             `json:"taskId"`
		FinishedAt    *model.LocalTime `json:"finishedAt"`
		Total         int              `json:"total"`
		Passed        int              `json:"passed"`
		Failed        int              `json:"failed"`
		PassRate      float64          `json:"passRate"`
		WeightedScore int              `json:"weightedScore"`
	}

	var points []trendPoint
	if err := h.db.Model(&model.KubeBaselineTask{}).
		Where("cluster_id = ? AND status = ?", clusterID, model.BaselineTaskDone).
		Order("id DESC").Limit(limit).
		Find(&points).Error; err != nil {
		h.logger.Error("查询基线趋势失败", zap.Error(err))
		InternalError(c, "查询基线趋势失败")
		return
	}
	// 反转为时间正序，便于前端直接画图
	for i, j := 0, len(points)-1; i < j; i, j = i+1, j-1 {
		points[i], points[j] = points[j], points[i]
	}
	Success(c, points)
}

// GetBaselineTaskDetail 单次基线任务详情（任务信息 + 该次 checklist）
func (h *KubeBaselineHandler) GetBaselineTaskDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	var task model.KubeBaselineTask
	if err := h.db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		InternalError(c, "查询任务失败")
		return
	}

	// 该次任务的检查项（可选按结果/类别过滤）
	q := h.db.Model(&model.KubeBaseline{}).Where("task_id = ?", task.ID)
	if result := c.Query("result"); result != "" {
		q = q.Where("result = ?", result)
	}
	if category := c.Query("category"); category != "" {
		q = q.Where("category = ?", category)
	}
	var checks []model.KubeBaseline
	q.Order("severity ASC, check_id ASC").Find(&checks)

	Success(c, gin.H{"task": task, "items": checks})
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

	taskID, err := h.checker.EnqueueCheck(*req.ClusterID)
	if err != nil {
		h.logger.Error("入队基线检查失败", zap.Error(err))
		InternalError(c, "内部服务错误")
		return
	}

	// 异步执行：立即返回 task_id，前端轮询 GET /kube/baseline-tasks/:id 取进度与结果
	Success(c, gin.H{
		"taskId": taskID,
		"status": model.BaselineTaskPending,
	})
}
