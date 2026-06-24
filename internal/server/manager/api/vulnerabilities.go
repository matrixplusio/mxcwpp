package api

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
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
	VulnCategory  string // P5.1: kernel/critical_shared_lib/shared_lib/system_daemon/cli_tool/web_service/db_service/container_runtime/virtualization/language_dep/other
	RestartAction string // P5.5: reboot_host/restart_dependent_services/restart_specific_service/no_action/rebuild_app/unknown
	// AssetType 资产维度: os/middleware/app/container/image/unknown
	// 决定 UI tab 归属和修复责任方,host_vulnerabilities 字段
	AssetType string
	// Subscope 细分: cloud_agent/monitoring_agent/security_agent/system_lib/os_package/business_binary/business_jar/unknown
	// 区分系统组件 vs 业务漏洞,解决误报"装了 docker?"问题
	Subscope string
	// FixOwner 修复责任方: ops/dev/dba/sre/image_maintainer/cloud_provider/apm_vendor/platform_team/unknown
	FixOwner string
	// CWECategory CWE 高级分类: rce/privesc/sqli/xss/info_disclosure/dos/path_traversal/ssrf/other
	CWECategory string
	// ShowAll true 显示所有 vuln(含 advisory orphan 库存); 默认 false 只显示集群有主机命中的
	// 解决用户疑惑:99% advisory inventory orphan 漏洞混在主列表里看着乱
	ShowAll bool
	Sort    string // priority_score / cvss_score
}

func (h *VulnerabilitiesHandler) buildVulnerabilityQuery(filter vulnerabilityListFilter) *gorm.DB {
	query := h.db.Model(&model.Vulnerability{})

	if filter.HostID != "" {
		query = query.Joins("JOIN host_vulnerabilities hv ON hv.vuln_id = vulnerabilities.id")
		query = query.Where("hv.host_id = ?", filter.HostID)
		query = query.Group("vulnerabilities.id")
	} else if !filter.ShowAll {
		// 默认隐藏 orphan advisory:只显示集群有主机命中的 vuln
		// (vulnerabilities.affected_hosts 字段不可信,有 stale 风险,用 EXISTS 实查)
		query = query.Where("EXISTS (SELECT 1 FROM host_vulnerabilities WHERE host_vulnerabilities.vuln_id = vulnerabilities.id)")
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

	// 分类 / 重启动作筛选（P5.1 + P5.5）— override 优先：COALESCE(override, base) = 用户选值
	if filter.VulnCategory != "" {
		query = query.Where(
			"COALESCE(NULLIF(vulnerabilities.vuln_category_override, ''), vulnerabilities.vuln_category) = ?",
			filter.VulnCategory)
	}
	if filter.RestartAction != "" {
		query = query.Where(
			"COALESCE(NULLIF(vulnerabilities.restart_action_override, ''), vulnerabilities.restart_action) = ?",
			filter.RestartAction)
	}
	if filter.CWECategory != "" {
		query = query.Where("vulnerabilities.cwe_category = ?", filter.CWECategory)
	}

	// 资产维度 / 修复责任方 / subscope 细分筛选(P-vuln-classify):字段在 host_vulnerabilities 上,需要 join
	if filter.AssetType != "" || filter.FixOwner != "" || filter.Subscope != "" {
		if filter.HostID == "" {
			// 全局 list 时未必已 join host_vulnerabilities,补 join
			query = query.Joins("JOIN host_vulnerabilities ahv ON ahv.vuln_id = vulnerabilities.id").
				Group("vulnerabilities.id")
			if filter.AssetType != "" {
				query = query.Where("ahv.asset_type = ?", filter.AssetType)
			}
			if filter.FixOwner != "" {
				query = query.Where("ahv.fix_owner = ?", filter.FixOwner)
			}
			if filter.Subscope != "" {
				query = query.Where("ahv.subscope = ?", filter.Subscope)
			}
		} else {
			// 已有 hv join,直接 where
			if filter.AssetType != "" {
				query = query.Where("hv.asset_type = ?", filter.AssetType)
			}
			if filter.FixOwner != "" {
				query = query.Where("hv.fix_owner = ?", filter.FixOwner)
			}
			if filter.Subscope != "" {
				query = query.Where("hv.subscope = ?", filter.Subscope)
			}
		}
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
		VulnCategory:  strings.TrimSpace(c.Query("vuln_category")),
		RestartAction: strings.TrimSpace(c.Query("restart_action")),
		AssetType:     strings.TrimSpace(c.Query("asset_type")),
		Subscope:      strings.TrimSpace(c.Query("subscope")),
		FixOwner:      strings.TrimSpace(c.Query("fix_owner")),
		CWECategory:   strings.TrimSpace(c.Query("cwe_category")),
		ShowAll:       c.Query("show_all") == "true",
		Sort:          strings.TrimSpace(c.Query("sort")),
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 200 { // 上限防超大 page_size 拖垮 DB
		pageSize = 200
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

	// 聚合 asset_type / fix_owner 到 vulnerability 顶层(全局列表 hosts 数组为空时用)
	// 取 GROUP BY vuln_id 的 MAX(asset_type)/MAX(fix_owner): 同 vuln 在多 host 一般同 asset_type
	if len(vulns) > 0 {
		vulnIDs := make([]uint, len(vulns))
		for i, v := range vulns {
			vulnIDs[i] = v.ID
		}
		type aggRow struct {
			VulnID         uint   `gorm:"column:vuln_id"`
			AssetType      string `gorm:"column:asset_type"`
			Subscope       string `gorm:"column:subscope"`
			FixOwner       string `gorm:"column:fix_owner"`
			HostBinaryPath string `gorm:"column:host_binary_path"`
		}
		var aggs []aggRow
		// 用 MAX() 取任一非 unknown 值,subscope/binary_path 同理(UI 提示性,非精确性要求)
		h.db.Raw(`
SELECT vuln_id,
  COALESCE(MAX(CASE WHEN asset_type<>'unknown' AND asset_type<>'' THEN asset_type END), 'unknown') AS asset_type,
  COALESCE(MAX(CASE WHEN subscope<>'unknown' AND subscope<>'' THEN subscope END), 'unknown') AS subscope,
  COALESCE(MAX(CASE WHEN fix_owner<>'unknown' AND fix_owner<>'' THEN fix_owner END), 'unknown') AS fix_owner,
  COALESCE(MAX(CASE WHEN host_binary_path<>'' THEN host_binary_path END), '') AS host_binary_path
FROM host_vulnerabilities WHERE vuln_id IN ?
GROUP BY vuln_id`, vulnIDs).Scan(&aggs)
		aggMap := make(map[uint]aggRow, len(aggs))
		for _, a := range aggs {
			aggMap[a.VulnID] = a
		}
		for i := range vulns {
			if a, ok := aggMap[vulns[i].ID]; ok {
				vulns[i].AssetType = a.AssetType
				vulns[i].Subscope = a.Subscope
				vulns[i].FixOwner = a.FixOwner
				vulns[i].HostBinaryPath = a.HostBinaryPath
			}
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

// TriggerScan 触发漏洞扫描
// POST /api/v1/vulnerabilities/scan
//
// 兼容两种参数:
//
//	旧: { scan_type: "full_scan" | "incremental_scan" } → 等价 scope=global
//	新: { scope: "global"|"hosts"|"business_line", host_ids: [], business_line: "" }
//
// 当 scope 字段存在时以 scope 为准（新字段优先）。
func (h *VulnerabilitiesHandler) TriggerScan(c *gin.Context) {
	var req struct {
		ScanType       string   `json:"scan_type"`
		Scope          string   `json:"scope"`
		HostIDs        []string `json:"host_ids"`
		BusinessLine   string   `json:"business_line"`
		SyncDB         *bool    `json:"sync_db"`
		ReconcileStale *bool    `json:"reconcile_stale"`
	}
	_ = c.ShouldBindJSON(&req)

	// 解析 scope（新字段优先；缺失时按旧 scan_type 推导）
	scope := req.Scope
	if scope == "" {
		scope = model.ScanScopeGlobal
	}
	if scope != model.ScanScopeGlobal && scope != model.ScanScopeHosts && scope != model.ScanScopeBusinessLine {
		BadRequest(c, "无效的 scope，支持 global / hosts / business_line")
		return
	}

	syncDB := false
	if req.SyncDB != nil {
		syncDB = *req.SyncDB
	}
	// 兼容旧 full_scan：等价于 global + sync_db=true
	if req.Scope == "" && req.ScanType == "full_scan" {
		syncDB = true
	}

	reconcileStale := true
	if req.ReconcileStale != nil {
		reconcileStale = *req.ReconcileStale
	}

	// 全局扫描沿用旧并发保护（DB 同步锁）
	if scope == model.ScanScopeGlobal {
		var running int64
		h.db.Model(&model.SecurityDBSyncRecord{}).
			Where("db_type IN ? AND status = ?", []string{"osv", "osv-incremental", "vuln-sync"}, "running").
			Count(&running)
		if running > 0 {
			BadRequest(c, "已有同步或扫描任务正在运行，请等待完成后再试")
			return
		}
	}

	triggeredBy := ""
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok {
			triggeredBy = s
		}
	}

	mgr := biz.NewScanTaskManager(h.db, h.logger)
	task, err := mgr.Create(biz.CreateTaskOpts{
		Scope:          scope,
		HostIDs:        req.HostIDs,
		BusinessLine:   req.BusinessLine,
		SyncDB:         syncDB,
		ReconcileStale: reconcileStale,
		TriggeredBy:    triggeredBy,
	})
	if err != nil {
		BadRequest(c, err.Error())
		return
	}

	// 异步执行
	go func(taskID string) {
		ctx := context.Background()
		if err := mgr.Execute(ctx, taskID); err != nil {
			h.logger.Error("targeted scan 执行失败",
				zap.String("task_id", taskID), zap.Error(err))
		}
	}(task.TaskID)

	estimated := 5 + task.ProgressTotal*2
	if syncDB {
		estimated += 600
	}

	Success(c, gin.H{
		"task_id":           task.TaskID,
		"scope":             task.Scope,
		"target_host_count": task.ProgressTotal,
		"estimated_seconds": estimated,
	})
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

// GetAssetTypeStats 按 asset_type × severity 统计漏洞数(host 维度)
// GET /api/v1/vulnerabilities/stats/asset-type?host_id=...&business_line=...
//
// 返回结构:
//
//	{
//	  "asset_types": [
//	    {"asset_type":"os","critical":0,"high":0,"medium":1,"low":0,"total":1},
//	    {"asset_type":"app","critical":8,"high":12,"medium":30,"low":2,"total":52},
//	    ...
//	  ],
//	  "fix_owners": [...同样结构 by fix_owner...]
//	}
//
// UI 主机详情漏洞 tab 用此 endpoint 渲染分类徽章 + 切换 tab 内容。
func (h *VulnerabilitiesHandler) GetAssetTypeStats(c *gin.Context) {
	hostID := strings.TrimSpace(c.Query("host_id"))
	businessLine := strings.TrimSpace(c.Query("business_line"))

	type bucket struct {
		Key      string `json:"key"`
		Critical int64  `json:"critical"`
		High     int64  `json:"high"`
		Medium   int64  `json:"medium"`
		Low      int64  `json:"low"`
		Total    int64  `json:"total"`
	}
	type rawRow struct {
		Group    string `gorm:"column:grp"`
		Severity string
		N        int64
	}

	buildQuery := func(groupCol string) *gorm.DB {
		q := h.db.Table("host_vulnerabilities AS hv").
			Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
			Where("hv.status = ?", "unpatched")
		if hostID != "" {
			q = q.Where("hv.host_id = ?", hostID)
		}
		if businessLine != "" {
			q = q.Joins("JOIN hosts h ON h.host_id = hv.host_id").
				Where("h.business_line = ?", businessLine)
		}
		return q.Select("hv." + groupCol + " AS grp, v.severity AS severity, COUNT(*) AS n").
			Group("hv." + groupCol + ", v.severity")
	}

	aggregate := func(rows []rawRow) []bucket {
		m := map[string]*bucket{}
		for _, r := range rows {
			b, ok := m[r.Group]
			if !ok {
				b = &bucket{Key: r.Group}
				m[r.Group] = b
			}
			switch r.Severity {
			case "critical":
				b.Critical = r.N
			case "high":
				b.High = r.N
			case "medium":
				b.Medium = r.N
			case "low":
				b.Low = r.N
			}
			b.Total += r.N
		}
		out := make([]bucket, 0, len(m))
		for _, b := range m {
			out = append(out, *b)
		}
		return out
	}

	var assetTypeRows []rawRow
	if err := buildQuery("asset_type").Scan(&assetTypeRows).Error; err != nil {
		h.logger.Error("asset_type stats query 失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	var fixOwnerRows []rawRow
	if err := buildQuery("fix_owner").Scan(&fixOwnerRows).Error; err != nil {
		h.logger.Error("fix_owner stats query 失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, gin.H{
		"asset_types": aggregate(assetTypeRows),
		"fix_owners":  aggregate(fixOwnerRows),
	})
}

// ExportByOwner 按修复责任方导出漏洞 CSV
// GET /api/v1/vulnerabilities/export-by-owner?fix_owner=dev[&asset_type=app&business_line=G02&severity=critical,high]
//
// 业务场景:漏洞分级分类后,需把工作量分派到对应团队:
//   - ops/sre/dba: OS / middleware 漏洞 → 直接 dnf update
//   - dev: app/language_dep → 业务程序 rebuild,需要 binary_path + module + fix_version
//   - image_maintainer: container/image → 镜像 rebuild,需要 image_id
//
// 导出列:host_id, hostname, ip, business_line, business_owner, business_contact,
//
//	cve, severity, cvss, cwe_category, asset_type, vuln_category,
//	component, current, fixed, restart_action, message
func (h *VulnerabilitiesHandler) ExportByOwner(c *gin.Context) {
	fixOwner := strings.TrimSpace(c.Query("fix_owner"))
	assetType := strings.TrimSpace(c.Query("asset_type"))
	subscope := strings.TrimSpace(c.Query("subscope"))
	businessLine := strings.TrimSpace(c.Query("business_line"))
	severity := strings.TrimSpace(c.Query("severity"))
	if fixOwner == "" && assetType == "" && subscope == "" {
		BadRequest(c, "必须指定 fix_owner 或 asset_type 或 subscope")
		return
	}

	type row struct {
		HostID          string `gorm:"column:host_id"`
		Hostname        string `gorm:"column:hostname"`
		IP              string `gorm:"column:ip"`
		BusinessLine    string `gorm:"column:business_line"`
		BusinessOwner   string `gorm:"column:bl_owner"`
		BusinessContact string `gorm:"column:bl_contact"`
		CVE             string `gorm:"column:cve_id"`
		Severity        string `gorm:"column:severity"`
		CVSS            float64
		CWECategory     string `gorm:"column:cwe_category"`
		AssetType       string `gorm:"column:asset_type"`
		Subscope        string `gorm:"column:subscope"`
		FixOwner        string `gorm:"column:fix_owner"`
		HostBinaryPath  string `gorm:"column:host_binary_path"`
		VulnCategory    string `gorm:"column:vuln_category"`
		Component       string
		Current         string `gorm:"column:current_version"`
		Fixed           string `gorm:"column:fixed_version"`
		RestartAction   string `gorm:"column:restart_action"`
		Message         string `gorm:"column:precheck_message"`
	}

	q := h.db.Table("host_vulnerabilities AS hv").
		Select(`hv.host_id,
			COALESCE(NULLIF(h.hostname, ''), hv.hostname) AS hostname,
			COALESCE(NULLIF(JSON_UNQUOTE(JSON_EXTRACT(h.ipv4, '$[0]')), ''), hv.ip) AS ip,
			h.business_line,
			bl.owner AS bl_owner, bl.contact AS bl_contact,
			v.cve_id, v.severity, v.cvss_score AS cvss, v.cwe_category,
			hv.asset_type, hv.subscope, hv.fix_owner, hv.host_binary_path, v.vuln_category,
			v.component, hv.current_version, v.fixed_version,
			v.restart_action, hv.precheck_message`).
		Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
		Joins("LEFT JOIN hosts h ON h.host_id = hv.host_id").
		Joins("LEFT JOIN business_lines bl ON bl.name = h.business_line").
		Where("hv.status = ?", "unpatched")
	if fixOwner != "" {
		q = q.Where("hv.fix_owner = ?", fixOwner)
	}
	if assetType != "" {
		q = q.Where("hv.asset_type = ?", assetType)
	}
	if subscope != "" {
		q = q.Where("hv.subscope = ?", subscope)
	}
	if businessLine != "" {
		q = q.Where("h.business_line = ?", businessLine)
	}
	if severity != "" {
		sevs := strings.Split(severity, ",")
		q = q.Where("v.severity IN ?", sevs)
	}
	q = q.Order("v.severity ASC, v.cvss_score DESC")

	var rows []row
	if err := q.Scan(&rows).Error; err != nil {
		h.logger.Error("export-by-owner query 失败", zap.Error(err))
		InternalError(c, "导出失败")
		return
	}

	fname := fmt.Sprintf("vulns_%s_%s_%s.csv",
		fixOwner, assetType, time.Now().Format("20060102_150405"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+fname+`"`)
	c.Status(http.StatusOK)
	if _, err := c.Writer.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil { // UTF-8 BOM, Excel 友好
		return
	}
	w := csv.NewWriter(c.Writer)
	defer w.Flush()
	_ = w.Write([]string{
		"host_id", "hostname", "ip", "business_line", "business_owner", "business_contact",
		"cve", "severity", "cvss", "cwe_category", "asset_type", "subscope", "fix_owner",
		"host_binary_path", "vuln_category", "component", "current_version", "fixed_version",
		"restart_action", "precheck_message",
	})
	for _, r := range rows {
		_ = w.Write([]string{
			r.HostID, r.Hostname, r.IP, r.BusinessLine, r.BusinessOwner, r.BusinessContact,
			r.CVE, r.Severity, fmt.Sprintf("%.1f", r.CVSS), r.CWECategory, r.AssetType, r.Subscope, r.FixOwner,
			r.HostBinaryPath, r.VulnCategory, r.Component, r.Current, r.Fixed,
			r.RestartAction, r.Message,
		})
	}
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
