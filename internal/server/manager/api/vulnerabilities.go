package api

import (
	"strconv"
	"strings"
	"time"

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
	HostID        string
	Search        string
	Severity      string
	Status        string
	Component     string
	ExploitStatus string // has_exploit / in_kev / none
	Ecosystem     string // OS / Go / npm / PyPI / Maven / Cargo
	Priority      string // high / medium-high / medium / low
	Sort          string // priority_score / cvss_score
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
			"vulnerabilities.cnvd_id LIKE ?",
			"vulnerabilities.cnnvd_id LIKE ?",
		}
		args := []interface{}{pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern}
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

	// 利用状态筛选
	switch filter.ExploitStatus {
	case "in_kev":
		query = query.Where("vulnerabilities.in_kev = ?", true)
	case "has_exploit":
		query = query.Where("vulnerabilities.has_exploit = ? AND vulnerabilities.in_kev = ?", true, false)
	case "none":
		query = query.Where("vulnerabilities.has_exploit = ?", false)
	}

	// 生态系统筛选
	if filter.Ecosystem != "" {
		query = query.Joins("JOIN host_vulnerabilities ehv ON ehv.vuln_id = vulnerabilities.id").
			Joins("JOIN software sw ON sw.host_id = ehv.host_id AND sw.name = vulnerabilities.component").
			Where("sw.ecosystem = ?", filter.Ecosystem).
			Group("vulnerabilities.id")
	}

	// 优先级筛选
	switch filter.Priority {
	case "high":
		query = query.Where("vulnerabilities.priority_score >= ?", 0.75)
	case "medium-high":
		query = query.Where("vulnerabilities.priority_score >= ? AND vulnerabilities.priority_score < ?", 0.50, 0.75)
	case "medium":
		query = query.Where("vulnerabilities.priority_score >= ? AND vulnerabilities.priority_score < ?", 0.25, 0.50)
	case "low":
		query = query.Where("vulnerabilities.priority_score < ?", 0.25)
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
// UpdateCategoryOverride PUT /api/v1/vulnerabilities/:id/category
// admin 手动覆盖漏洞分类 / 重启动作（auto categorize 错时的兜底）。
// body: {vuln_category_override?: string, restart_action_override?: string}
// 空字符串 = 清除 override 回归 auto
func (h *VulnerabilitiesHandler) UpdateCategoryOverride(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的漏洞 ID")
		return
	}
	var req struct {
		VulnCategoryOverride  *string `json:"vuln_category_override"`
		RestartActionOverride *string `json:"restart_action_override"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数无效")
		return
	}
	updates := map[string]any{}
	if req.VulnCategoryOverride != nil {
		updates["vuln_category_override"] = *req.VulnCategoryOverride
	}
	if req.RestartActionOverride != nil {
		updates["restart_action_override"] = *req.RestartActionOverride
	}
	if len(updates) == 0 {
		BadRequest(c, "至少需提供 vuln_category_override 或 restart_action_override")
		return
	}
	if err := h.db.Model(&model.Vulnerability{}).
		Where("id = ?", id).UpdateColumns(updates).Error; err != nil {
		h.logger.Error("更新漏洞分类 override 失败", zap.Uint64("id", id), zap.Error(err))
		InternalError(c, "更新失败")
		return
	}
	Success(c, gin.H{"id": id, "updated": updates})
}

func (h *VulnerabilitiesHandler) ListVulnerabilities(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	filter := vulnerabilityListFilter{
		HostID:        strings.TrimSpace(c.Query("host_id")),
		Search:        strings.TrimSpace(c.Query("search")),
		Severity:      strings.TrimSpace(c.Query("severity")),
		Status:        strings.TrimSpace(c.Query("status")),
		Component:     strings.TrimSpace(c.Query("component")),
		ExploitStatus: strings.TrimSpace(c.Query("exploit_status")),
		Priority:      strings.TrimSpace(c.Query("priority")),
		Ecosystem:     strings.TrimSpace(c.Query("ecosystem")),
		Sort:          strings.TrimSpace(c.Query("sort")),
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
	// 排序
	orderClause := "vulnerabilities.discovered_at DESC"
	switch filter.Sort {
	case "priority_score":
		orderClause = "vulnerabilities.priority_score DESC"
	case "cvss_score":
		orderClause = "vulnerabilities.cvss_score DESC"
	}

	if err := query.Preload("Hosts", preloadHosts).
		Offset(offset).Limit(pageSize).
		Order(orderClause).
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
// 支持 scan_type 参数：full_scan（全量，默认）/ incremental_scan（增量）
func (h *VulnerabilitiesHandler) TriggerScan(c *gin.Context) {
	var req struct {
		ScanType string `json:"scan_type"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.ScanType == "" {
		req.ScanType = "full_scan"
	}
	if req.ScanType != "full_scan" && req.ScanType != "incremental_scan" {
		BadRequest(c, "无效的扫描类型，支持 full_scan / incremental_scan")
		return
	}

	// 并发保护：检查是否有正在运行的同步/扫描任务
	var running int64
	h.db.Model(&model.SecurityDBSyncRecord{}).
		Where("db_type IN ? AND status = ?", []string{"osv", "osv-incremental", "vuln-sync"}, "running").
		Count(&running)
	if running > 0 {
		BadRequest(c, "已有同步或扫描任务正在运行，请等待完成后再试")
		return
	}

	scanner := biz.NewVulnScanner(h.db, h.logger)

	if req.ScanType == "incremental_scan" {
		go func() {
			if err := scanner.ScanIncremental(); err != nil {
				h.logger.Error("增量扫描失败", zap.Error(err))
			}
		}()
		SuccessMessage(c, "增量扫描任务已启动")
	} else {
		go func() {
			if err := scanner.ScanAll(); err != nil {
				h.logger.Error("漏洞扫描失败", zap.Error(err))
			}
		}()
		SuccessMessage(c, "全量扫描任务已启动")
	}
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

// GetPriorityStats 漏洞优先级分布统计
// GET /api/v1/vulnerabilities/stats/priority
func (h *VulnerabilitiesHandler) GetPriorityStats(c *gin.Context) {
	type PriorityBucket struct {
		Level string `json:"level"`
		Count int64  `json:"count"`
	}

	var results []PriorityBucket

	// 高优先级 >= 0.75
	var high int64
	h.db.Model(&model.Vulnerability{}).Where("status = ? AND priority_score >= ?", "unpatched", 0.75).Count(&high)
	results = append(results, PriorityBucket{Level: "high", Count: high})

	// 中高 0.50-0.75
	var mediumHigh int64
	h.db.Model(&model.Vulnerability{}).Where("status = ? AND priority_score >= ? AND priority_score < ?", "unpatched", 0.50, 0.75).Count(&mediumHigh)
	results = append(results, PriorityBucket{Level: "medium-high", Count: mediumHigh})

	// 中 0.25-0.50
	var medium int64
	h.db.Model(&model.Vulnerability{}).Where("status = ? AND priority_score >= ? AND priority_score < ?", "unpatched", 0.25, 0.50).Count(&medium)
	results = append(results, PriorityBucket{Level: "medium", Count: medium})

	// 低 < 0.25
	var low int64
	h.db.Model(&model.Vulnerability{}).Where("status = ? AND priority_score < ?", "unpatched", 0.25).Count(&low)
	results = append(results, PriorityBucket{Level: "low", Count: low})

	Success(c, results)
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

// GetScanHistoryDetail 获取单条扫描记录详情（含本次新增的漏洞列表）
// GET /api/v1/vulnerabilities/scan-history/:id
func (h *VulnerabilitiesHandler) GetScanHistoryDetail(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == 0 {
		BadRequest(c, "无效的记录 ID")
		return
	}

	var record model.SecurityDBSyncRecord
	if err := h.db.First(&record, id).Error; err != nil {
		NotFound(c, "扫描记录不存在")
		return
	}

	vulnPage, _ := strconv.Atoi(c.DefaultQuery("vulnPage", "1"))
	vulnPageSize, _ := strconv.Atoi(c.DefaultQuery("vulnPageSize", "20"))
	if vulnPage < 1 {
		vulnPage = 1
	}
	if vulnPageSize < 1 || vulnPageSize > 100 {
		vulnPageSize = 20
	}

	// 时间窗口：扫描开始 → 扫描开始 + 耗时
	windowEnd := record.StartedAt.Add(time.Duration(record.Duration+60) * time.Second) // +60s 容差
	if record.Status == "running" {
		windowEnd = time.Now()
	}

	var vulnTotal int64
	h.db.Model(&model.Vulnerability{}).
		Where("created_at >= ? AND created_at <= ?", record.StartedAt, windowEnd).
		Count(&vulnTotal)

	var vulns []model.Vulnerability
	h.db.Where("created_at >= ? AND created_at <= ?", record.StartedAt, windowEnd).
		Order("cvss_score DESC").
		Offset((vulnPage - 1) * vulnPageSize).
		Limit(vulnPageSize).
		Find(&vulns)

	// 受影响主机
	type affectedHost struct {
		HostID    string `json:"hostId"`
		Hostname  string `json:"hostname"`
		IP        string `json:"ip"`
		VulnCount int64  `json:"vulnCount"`
	}
	var hosts []affectedHost
	h.db.Model(&model.HostVulnerability{}).
		Select("host_id, hostname, ip, COUNT(*) as vuln_count").
		Where("created_at >= ? AND created_at <= ?", record.StartedAt, windowEnd).
		Group("host_id, hostname, ip").
		Order("vuln_count DESC").
		Limit(100).
		Find(&hosts)

	Success(c, gin.H{
		"record": record,
		"vulns": gin.H{
			"items": vulns,
			"total": vulnTotal,
			"page":  vulnPage,
		},
		"affectedHosts": hosts,
	})
}
