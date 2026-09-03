package api

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// MemoryThreatHandler 内存威胁 API 处理器
type MemoryThreatHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewMemoryThreatHandler 创建内存威胁 API 处理器
func NewMemoryThreatHandler(db *gorm.DB, logger *zap.Logger) *MemoryThreatHandler {
	return &MemoryThreatHandler{db: db, logger: logger}
}

// ListMemoryThreats 查看内存威胁列表
func (h *MemoryThreatHandler) ListMemoryThreats(c *gin.Context) {
	hostID := c.Query("host_id")
	threatType := c.Query("threat_type")
	severity := c.Query("severity")
	status := c.Query("status")

	query := h.db.Model(&model.MemoryThreat{})
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if threatType != "" {
		query = query.Where("threat_type = ?", threatType)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	query = query.Order("created_at DESC")

	var total int64
	if err := query.Count(&total).Error; err != nil {
		InternalError(c, "查询内存威胁失败")
		return
	}

	page, pageSize := ParsePagination(c)
	var threats []model.MemoryThreat
	if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&threats).Error; err != nil {
		InternalError(c, "查询内存威胁失败")
		return
	}

	SuccessPaginated(c, total, threats)
}

// GetMemoryThreatStats 内存威胁统计概览
//
// 性能:原 4 个 COUNT 串行 ~1s,合并成 1 个 SELECT 多个 conditional aggregate +
// 1 个 GROUP BY,2 query 并发后 ~50-100ms。
func (h *MemoryThreatHandler) GetMemoryThreatStats(c *gin.Context) {
	type aggRow struct {
		Total        int64
		OpenCnt      int64
		CriticalOpen int64
	}
	var agg aggRow

	// Count by threat type
	type typeCount struct {
		ThreatType string `json:"threat_type"`
		Count      int64  `json:"count"`
	}
	var typeCounts []typeCount

	g := new(errgroup.Group)

	// 合并 3 个 COUNT 为 1 个 conditional aggregate query
	g.Go(func() error {
		return h.db.Model(&model.MemoryThreat{}).
			Select(`COUNT(*) AS total,
			        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_cnt,
			        SUM(CASE WHEN severity = 'critical' AND status = 'open' THEN 1 ELSE 0 END) AS critical_open`).
			Scan(&agg).Error
	})

	g.Go(func() error {
		return h.db.Model(&model.MemoryThreat{}).
			Select("threat_type, count(*) as count").
			Where("status = ?", "open").
			Group("threat_type").
			Find(&typeCounts).Error
	})

	if err := g.Wait(); err != nil {
		h.logger.Warn("内存威胁统计查询失败", zap.Error(err))
	}

	Success(c, gin.H{
		"total":          agg.Total,
		"open":           agg.OpenCnt,
		"critical_open":  agg.CriticalOpen,
		"by_threat_type": typeCounts,
	})
}

// ResolveMemoryThreat 标记内存威胁为已处理
func (h *MemoryThreatHandler) ResolveMemoryThreat(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Status string `json:"status"` // resolved / false_positive
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数无效")
		return
	}
	if req.Status != "resolved" && req.Status != "false_positive" {
		BadRequest(c, "status 必须为 resolved 或 false_positive")
		return
	}

	result := h.db.Model(&model.MemoryThreat{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":      req.Status,
			"resolved_by": c.GetString("username"),
		})
	if result.RowsAffected == 0 {
		NotFound(c, "内存威胁不存在")
		return
	}
	SuccessMessage(c, "内存威胁已处理")
}
