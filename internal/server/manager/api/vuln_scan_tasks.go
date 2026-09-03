package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// GetScanTask 查单个扫描任务进度
// GET /api/v1/vulnerabilities/scan-tasks/:task_id
func (h *VulnerabilitiesHandler) GetScanTask(c *gin.Context) {
	taskID := c.Param("task_id")
	var task model.VulnScanTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		NotFound(c, "扫描任务不存在")
		return
	}
	Success(c, task)
}

// ListScanTasks 列出扫描任务（按 created_at 降序）
// GET /api/v1/vulnerabilities/scan-tasks?status=running&limit=20
func (h *VulnerabilitiesHandler) ListScanTasks(c *gin.Context) {
	status := c.Query("status")
	limit := 20
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
			if limit > 100 {
				limit = 100
			}
		}
	}

	q := h.db.Model(&model.VulnScanTask{}).Order("created_at DESC")
	if status != "" {
		q = q.Where("status = ?", status)
	}

	var tasks []model.VulnScanTask
	if err := q.Limit(limit).Find(&tasks).Error; err != nil {
		InternalError(c, "查询扫描任务失败")
		return
	}
	Success(c, gin.H{"items": tasks, "count": len(tasks)})
}
