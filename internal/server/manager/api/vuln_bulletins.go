package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// VulnBulletinsHandler 漏洞通报 API
type VulnBulletinsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewVulnBulletinsHandler 创建漏洞通报 Handler
func NewVulnBulletinsHandler(db *gorm.DB, logger *zap.Logger) *VulnBulletinsHandler {
	return &VulnBulletinsHandler{db: db, logger: logger}
}

// ListBulletins 通报列表
func (h *VulnBulletinsHandler) ListBulletins(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	query := h.db.Model(&model.VulnBulletin{})

	// 筛选条件
	if priority := c.Query("priority"); priority != "" {
		query = query.Where("priority = ?", priority)
	}
	if status := c.Query("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	if cveID := c.Query("cve_id"); cveID != "" {
		query = query.Where("cve_id LIKE ?", "%"+cveID+"%")
	}
	if component := c.Query("component"); component != "" {
		query = query.Where("component LIKE ?", "%"+component+"%")
	}
	if search := c.Query("search"); search != "" {
		query = query.Where("cve_id LIKE ? OR component LIKE ? OR bulletin_no LIKE ? OR description LIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}
	if slaBreached := c.Query("sla_breached"); slaBreached == "true" {
		query = query.Where("sla_breached = ?", true)
	}

	// 统计
	var total int64
	query.Count(&total)

	// 排序
	sort := c.DefaultQuery("sort", "-created_at")
	switch sort {
	case "priority":
		query = query.Order("FIELD(priority, 'P0', 'P1', 'P2', 'P3'), created_at DESC")
	case "-priority":
		query = query.Order("FIELD(priority, 'P3', 'P2', 'P1', 'P0'), created_at DESC")
	case "cvss_score":
		query = query.Order("cvss_score ASC")
	case "-cvss_score":
		query = query.Order("cvss_score DESC")
	case "created_at":
		query = query.Order("created_at ASC")
	default:
		query = query.Order("created_at DESC")
	}

	var bulletins []model.VulnBulletin
	query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&bulletins)

	SuccessPaginated(c, total, bulletins)
}

// GetBulletin 通报详情
func (h *VulnBulletinsHandler) GetBulletin(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的通报 ID")
		return
	}

	var bulletin model.VulnBulletin
	if err := h.db.First(&bulletin, id).Error; err != nil {
		NotFound(c, "通报不存在")
		return
	}

	// 查询受影响主机列表
	var hosts []model.HostVulnerability
	h.db.Where("vuln_id = ?", bulletin.VulnID).Find(&hosts)

	Success(c, gin.H{
		"bulletin":       bulletin,
		"affected_hosts": hosts,
	})
}

// AcknowledgeBulletin 确认通报
func (h *VulnBulletinsHandler) AcknowledgeBulletin(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的通报 ID")
		return
	}

	username := c.GetString("username")
	svc := biz.NewVulnBulletinService(h.db, h.logger)
	if err := svc.Acknowledge(uint(id), username); err != nil {
		InternalError(c, "确认通报失败")
		return
	}

	SuccessMessage(c, "通报已确认")
}

// ResolveBulletin 修复通报
func (h *VulnBulletinsHandler) ResolveBulletin(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的通报 ID")
		return
	}

	var body struct {
		Comment string `json:"comment"`
	}
	_ = c.ShouldBindJSON(&body)

	username := c.GetString("username")
	svc := biz.NewVulnBulletinService(h.db, h.logger)
	if err := svc.Resolve(uint(id), username, body.Comment); err != nil {
		InternalError(c, "修复通报失败")
		return
	}

	SuccessMessage(c, "通报已标记为修复")
}

// IgnoreBulletin 忽略通报
func (h *VulnBulletinsHandler) IgnoreBulletin(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的通报 ID")
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	username := c.GetString("username")
	svc := biz.NewVulnBulletinService(h.db, h.logger)
	if err := svc.Ignore(uint(id), username, body.Reason); err != nil {
		InternalError(c, "忽略通报失败")
		return
	}

	SuccessMessage(c, "通报已忽略")
}

// ReopenBulletin 重新打开通报
func (h *VulnBulletinsHandler) ReopenBulletin(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的通报 ID")
		return
	}

	svc := biz.NewVulnBulletinService(h.db, h.logger)
	if err := svc.Reopen(uint(id)); err != nil {
		InternalError(c, "重新打开通报失败")
		return
	}

	SuccessMessage(c, "通报已重新打开")
}

// BatchBulletins 批量操作
func (h *VulnBulletinsHandler) BatchBulletins(c *gin.Context) {
	var body struct {
		IDs    []uint `json:"ids" binding:"required"`
		Action string `json:"action" binding:"required"` // acknowledge/resolve/ignore
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	if body.Action != "acknowledge" && body.Action != "resolve" && body.Action != "ignore" {
		BadRequest(c, "不支持的操作: "+body.Action)
		return
	}

	username := c.GetString("username")
	svc := biz.NewVulnBulletinService(h.db, h.logger)
	if err := svc.BatchAction(body.IDs, body.Action, username, body.Reason); err != nil {
		InternalError(c, "批量操作失败")
		return
	}

	SuccessMessage(c, "批量操作完成")
}

// GetBulletinStatistics 通报统计
func (h *VulnBulletinsHandler) GetBulletinStatistics(c *gin.Context) {
	svc := biz.NewVulnBulletinService(h.db, h.logger)
	stats := svc.GetStatistics()
	Success(c, stats)
}

// GetBulletinConfig 获取通报配置
func (h *VulnBulletinsHandler) GetBulletinConfig(c *gin.Context) {
	svc := biz.NewVulnBulletinService(h.db, h.logger)
	cfg := svc.GetConfig()
	Success(c, cfg)
}

// UpdateBulletinConfig 更新通报配置
func (h *VulnBulletinsHandler) UpdateBulletinConfig(c *gin.Context) {
	var cfg model.VulnBulletinConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	svc := biz.NewVulnBulletinService(h.db, h.logger)
	if err := svc.SaveConfig(cfg); err != nil {
		InternalError(c, "保存配置失败")
		return
	}

	SuccessMessage(c, "配置已保存")
}
