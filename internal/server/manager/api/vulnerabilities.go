package api

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// VulnerabilitiesHandler 漏洞管理 API 处理器
type VulnerabilitiesHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewVulnerabilitiesHandler 创建漏洞处理器
func NewVulnerabilitiesHandler(db *gorm.DB, logger *zap.Logger) *VulnerabilitiesHandler {
	return &VulnerabilitiesHandler{db: db, logger: logger}
}

type vulnerabilityListFilter struct {
	HostID    string
	Search    string
	Severity  string
	Status    string
	Component string
}

func (h *VulnerabilitiesHandler) buildVulnerabilityQuery(filter vulnerabilityListFilter) *gorm.DB {
	query := h.db.Model(&model.Vulnerability{})

	if filter.HostID != "" {
		query = query.Joins("JOIN host_vulnerabilities hv ON hv.vuln_id = vulnerabilities.id")
		query = query.Where("hv.host_id = ?", filter.HostID)
		query = query.Group("vulnerabilities.id")
	}

	if filter.Search != "" {
		pattern := "%" + filter.Search + "%"
		clauses := []string{
			"vulnerabilities.cve_id LIKE ?",
			"vulnerabilities.osv_id LIKE ?",
			"vulnerabilities.description LIKE ?",
			"vulnerabilities.component LIKE ?",
			"vulnerabilities.current_version LIKE ?",
			"vulnerabilities.fixed_version LIKE ?",
		}
		args := []interface{}{pattern, pattern, pattern, pattern, pattern, pattern}
		if filter.HostID != "" {
			clauses = append(clauses, "hv.hostname LIKE ?", "hv.ip LIKE ?", "hv.current_version LIKE ?")
			args = append(args, pattern, pattern, pattern)
		}
		query = query.Where(strings.Join(clauses, " OR "), args...)
	}
	if filter.Component != "" {
		query = query.Where("vulnerabilities.component LIKE ?", "%"+filter.Component+"%")
	}
	if filter.Severity != "" {
		query = query.Where("vulnerabilities.severity = ?", filter.Severity)
	}
	if filter.Status != "" {
		if filter.HostID != "" {
			query = query.Where("hv.status = ?", filter.Status)
		} else {
			query = query.Where("vulnerabilities.status = ?", filter.Status)
		}
	}

	return query
}

func (h *VulnerabilitiesHandler) countAffectedHosts(filter vulnerabilityListFilter) int64 {
	if filter.HostID != "" {
		var count int64
		if err := h.db.Model(&model.HostVulnerability{}).
			Where("host_id = ?", filter.HostID).
			Count(&count).Error; err == nil && count > 0 {
			return 1
		}
		return 0
	}

	query := h.db.Table("host_vulnerabilities AS hv").
		Joins("JOIN vulnerabilities ON vulnerabilities.id = hv.vuln_id").
		Distinct("hv.host_id")

	if filter.Search != "" {
		pattern := "%" + filter.Search + "%"
		query = query.Where(
			"vulnerabilities.cve_id LIKE ? OR vulnerabilities.osv_id LIKE ? OR vulnerabilities.description LIKE ? OR vulnerabilities.component LIKE ? OR hv.hostname LIKE ? OR hv.ip LIKE ? OR hv.current_version LIKE ?",
			pattern, pattern, pattern, pattern, pattern, pattern, pattern,
		)
	}
	if filter.Component != "" {
		query = query.Where("vulnerabilities.component LIKE ?", "%"+filter.Component+"%")
	}
	if filter.Severity != "" {
		query = query.Where("vulnerabilities.severity = ?", filter.Severity)
	}
	if filter.Status != "" {
		query = query.Where("hv.status = ?", filter.Status)
	}

	var affectedHosts int64
	query.Count(&affectedHosts)
	return affectedHosts
}

// ListVulnerabilities 获取漏洞列表
// GET /api/v1/vulnerabilities
func (h *VulnerabilitiesHandler) ListVulnerabilities(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	filter := vulnerabilityListFilter{
		HostID:    strings.TrimSpace(c.Query("host_id")),
		Search:    strings.TrimSpace(c.Query("search")),
		Severity:  strings.TrimSpace(c.Query("severity")),
		Status:    strings.TrimSpace(c.Query("status")),
		Component: strings.TrimSpace(c.Query("component")),
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}

	query := h.buildVulnerabilityQuery(filter)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询漏洞总数失败", zap.Error(err))
		InternalError(c, "查询漏洞列表失败")
		return
	}

	var vulns []model.Vulnerability
	offset := (page - 1) * pageSize
	preloadHosts := func(db *gorm.DB) *gorm.DB {
		if filter.HostID != "" {
			db = db.Where("host_id = ?", filter.HostID)
		}
		if filter.Status != "" {
			db = db.Where("status = ?", filter.Status)
		}
		return db.Order("updated_at DESC")
	}
	if err := query.Preload("Hosts", preloadHosts).
		Offset(offset).Limit(pageSize).
		Order("vulnerabilities.discovered_at DESC").
		Find(&vulns).Error; err != nil {
		h.logger.Error("查询漏洞列表失败", zap.Error(err))
		InternalError(c, "查询漏洞列表失败")
		return
	}

	for i := range vulns {
		if filter.HostID != "" {
			vulns[i].AffectedHosts = len(vulns[i].Hosts)
		}
	}

	statsFilter := filter
	if statsFilter.Status == "" {
		statsFilter.Status = "unpatched"
	}

	var severityRows []struct {
		Severity string `gorm:"column:severity"`
		Count    int64  `gorm:"column:count"`
	}
	if err := h.buildVulnerabilityQuery(statsFilter).
		Select("vulnerabilities.severity, COUNT(DISTINCT vulnerabilities.id) as count").
		Group("vulnerabilities.severity").
		Scan(&severityRows).Error; err != nil {
		h.logger.Warn("统计漏洞级别分布失败", zap.Error(err))
	}

	var statsTotal int64
	if err := h.buildVulnerabilityQuery(statsFilter).Count(&statsTotal).Error; err != nil {
		h.logger.Warn("统计漏洞总数失败", zap.Error(err))
	}

	var critical, high int64
	for _, row := range severityRows {
		switch row.Severity {
		case "critical":
			critical = row.Count
		case "high":
			high = row.Count
		}
	}

	affectedHosts := h.countAffectedHosts(statsFilter)

	Success(c, gin.H{
		"items": vulns,
		"total": total,
		"stats": gin.H{
			"total":         statsTotal,
			"critical":      critical,
			"high":          high,
			"affectedHosts": affectedHosts,
		},
	})
}

// GetVulnerability 获取单个漏洞详情
// GET /api/v1/vulnerabilities/:id
func (h *VulnerabilitiesHandler) GetVulnerability(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的漏洞 ID")
		return
	}

	var vuln model.Vulnerability
	if err := h.db.Preload("Hosts").First(&vuln, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "漏洞不存在")
			return
		}
		h.logger.Error("查询漏洞详情失败", zap.Error(err))
		InternalError(c, "查询漏洞详情失败")
		return
	}

	Success(c, vuln)
}

// IgnoreVulnerability 忽略漏洞
// POST /api/v1/vulnerabilities/:id/ignore
func (h *VulnerabilitiesHandler) IgnoreVulnerability(c *gin.Context) {
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

	username, _ := c.Get("username")
	ignoredBy, _ := username.(string)

	txErr := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&vuln).Update("status", "ignored").Error; err != nil {
			return err
		}
		if err := tx.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", vuln.ID, "unpatched").
			Update("status", "ignored").Error; err != nil {
			return err
		}
		return nil
	})
	if txErr != nil {
		h.logger.Error("忽略漏洞失败", zap.Uint("id", vuln.ID), zap.Error(txErr))
		InternalError(c, "忽略漏洞失败")
		return
	}

	h.logger.Info("漏洞已忽略",
		zap.Uint64("vuln_id", id),
		zap.String("cve_id", vuln.CveID),
		zap.String("severity", vuln.Severity),
		zap.String("ignored_by", ignoredBy))

	SuccessMessage(c, "漏洞已忽略")
}

// UnignoreVulnerability 取消忽略漏洞
// POST /api/v1/vulnerabilities/:id/unignore
func (h *VulnerabilitiesHandler) UnignoreVulnerability(c *gin.Context) {
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

	if vuln.Status != "ignored" {
		BadRequest(c, "只有已忽略的漏洞才能取消忽略")
		return
	}

	txErr := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&vuln).Update("status", "unpatched").Error; err != nil {
			return err
		}
		if err := tx.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", vuln.ID, "ignored").
			Update("status", "unpatched").Error; err != nil {
			return err
		}
		return nil
	})
	if txErr != nil {
		h.logger.Error("取消忽略漏洞失败", zap.Uint("id", vuln.ID), zap.Error(txErr))
		InternalError(c, "取消忽略失败")
		return
	}

	username, _ := c.Get("username")
	unignoredBy, _ := username.(string)
	h.logger.Info("漏洞已取消忽略",
		zap.Uint64("vuln_id", id),
		zap.String("cve_id", vuln.CveID),
		zap.String("unignored_by", unignoredBy))

	SuccessMessage(c, "漏洞已取消忽略")
}

// TriggerSync 触发漏洞库同步（仅同步 NVD + Red Hat 数据，不执行主机扫描）
// POST /api/v1/vulnerabilities/sync
func (h *VulnerabilitiesHandler) TriggerSync(c *gin.Context) {
	// 并发保护：检查是否有正在运行的同步/扫描任务
	var running int64
	h.db.Model(&model.SecurityDBSyncRecord{}).
		Where("db_type IN ? AND status = ?", []string{"osv", "vuln-sync"}, "running").
		Count(&running)
	if running > 0 {
		BadRequest(c, "已有同步或扫描任务正在运行，请等待完成后再试")
		return
	}

	scanner := biz.NewVulnScanner(h.db, h.logger)

	go func() {
		if err := scanner.SyncOnly(); err != nil {
			h.logger.Error("漏洞库同步失败", zap.Error(err))
		}
	}()

	SuccessMessage(c, "漏洞库同步任务已启动")
}

// TriggerScan 触发漏洞扫描（包含漏洞库同步 + 主机扫描）
// POST /api/v1/vulnerabilities/scan
func (h *VulnerabilitiesHandler) TriggerScan(c *gin.Context) {
	// 并发保护：检查是否有正在运行的同步/扫描任务
	var running int64
	h.db.Model(&model.SecurityDBSyncRecord{}).
		Where("db_type IN ? AND status = ?", []string{"osv", "vuln-sync"}, "running").
		Count(&running)
	if running > 0 {
		BadRequest(c, "已有同步或扫描任务正在运行，请等待完成后再试")
		return
	}

	scanner := biz.NewVulnScanner(h.db, h.logger)

	go func() {
		if err := scanner.ScanAll(); err != nil {
			h.logger.Error("漏洞扫描失败", zap.Error(err))
		}
	}()

	SuccessMessage(c, "漏洞扫描任务已启动")
}

// GetScanStatus 获取漏洞扫描最新同步状态
// GET /api/v1/vulnerabilities/scan-status
func (h *VulnerabilitiesHandler) GetScanStatus(c *gin.Context) {
	scanner := biz.NewVulnScanner(h.db, h.logger)
	record, err := scanner.GetLatestSyncStatus()
	if err != nil {
		h.logger.Error("查询漏洞扫描状态失败", zap.Error(err))
		InternalError(c, "查询扫描状态失败")
		return
	}
	if record == nil {
		Success(c, gin.H{"status": "never", "message": "尚未执行过扫描"})
		return
	}
	Success(c, record)
}

// GetScanHistory 获取漏洞扫描历史记录
// GET /api/v1/vulnerabilities/scan-history
func (h *VulnerabilitiesHandler) GetScanHistory(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	scanner := biz.NewVulnScanner(h.db, h.logger)
	records, total, err := scanner.GetSyncHistory(page, pageSize)
	if err != nil {
		h.logger.Error("查询漏洞扫描历史失败", zap.Error(err))
		InternalError(c, "查询扫描历史失败")
		return
	}

	Success(c, gin.H{
		"total": total,
		"items": records,
	})
}
