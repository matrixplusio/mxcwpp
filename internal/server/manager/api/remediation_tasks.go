package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// detectPackageManager 根据主机 OS 和版本判断应使用的包管理器类型
// 返回值与 RemediationCommand.PackageType 对应：rpm-yum / rpm-dnf / deb
func detectPackageManager(osFamily, osVersion string) string {
	osLower := strings.ToLower(osFamily)

	switch osLower {
	case "debian", "ubuntu":
		return "deb"
	case "fedora":
		// Fedora 22+ 默认 dnf
		return "rpm-dnf"
	case "centos":
		// CentOS 8+ 使用 dnf
		major := parseMajorVersion(osVersion)
		if major >= 8 {
			return "rpm-dnf"
		}
		return "rpm-yum"
	case "rocky", "almalinux", "alma":
		// Rocky/AlmaLinux 均为 8+，默认 dnf
		return "rpm-dnf"
	case "rhel":
		// RHEL 8+ 使用 dnf
		major := parseMajorVersion(osVersion)
		if major >= 8 {
			return "rpm-dnf"
		}
		return "rpm-yum"
	case "oracle":
		// Oracle Linux 8+ 使用 dnf
		major := parseMajorVersion(osVersion)
		if major >= 8 {
			return "rpm-dnf"
		}
		return "rpm-yum"
	default:
		// 无法识别的 RPM 系发行版，yum 兜底（多数 dnf 系统上 yum 是软链接）
		return "rpm-yum"
	}
}

// parseMajorVersion 从版本号字符串中提取主版本号（如 "9.3" → 9）
func parseMajorVersion(version string) int {
	if version == "" {
		return 0
	}
	parts := strings.SplitN(version, ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return major
}

// selectCommandForHost 根据主机 OS 选择正确的包管理器命令
func selectCommandForHost(commands []biz.RemediationCommand, osFamily, osVersion string) string {
	if len(commands) == 0 {
		return ""
	}

	// 如果只有一条命令（PURL 已确定包管理器），直接使用
	if len(commands) == 1 {
		return commands[0].Command
	}

	pkgMgr := detectPackageManager(osFamily, osVersion)

	for _, cmd := range commands {
		if cmd.PackageType == pkgMgr {
			return cmd.Command
		}
	}

	// 降级匹配：rpm-dnf/rpm-yum 互相兼容（dnf 系统上 yum 是软链接）
	if strings.HasPrefix(pkgMgr, "rpm-") {
		for _, cmd := range commands {
			if strings.HasPrefix(cmd.PackageType, "rpm") {
				return cmd.Command
			}
		}
	}

	// 兜底：返回第一条
	return commands[0].Command
}

// RemediationTasksHandler 修复任务 API 处理器
type RemediationTasksHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewRemediationTasksHandler 创建修复任务处理器
func NewRemediationTasksHandler(db *gorm.DB, logger *zap.Logger) *RemediationTasksHandler {
	return &RemediationTasksHandler{db: db, logger: logger}
}

// CreateTask 创建修复任务
// POST /api/v1/remediation-tasks
func (h *RemediationTasksHandler) CreateTask(c *gin.Context) {
	var req struct {
		VulnID  uint     `json:"vulnId" binding:"required"`
		HostIDs []string `json:"hostIds" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数无效：需要 vulnId 和 hostIds")
		return
	}

	// 查询漏洞信息
	var vuln model.Vulnerability
	if err := h.db.First(&vuln, req.VulnID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "漏洞不存在")
			return
		}
		InternalError(c, "查询漏洞失败")
		return
	}

	// 查询受影响的主机关联
	var hostVulns []model.HostVulnerability
	h.db.Where("vuln_id = ? AND host_id IN ? AND status = ?", vuln.ID, req.HostIDs, "unpatched").Find(&hostVulns)
	if len(hostVulns) == 0 {
		BadRequest(c, "指定主机上无未修复的漏洞")
		return
	}

	// 生成修复命令
	remSvc := biz.NewRemediationService(h.db, h.logger)
	advice := remSvc.GetAdvice(&vuln)

	// 查询主机 OS 信息用于选择正确的包管理器命令
	hostIDs := make([]string, 0, len(hostVulns))
	for _, hv := range hostVulns {
		hostIDs = append(hostIDs, hv.HostID)
	}
	var hosts []model.Host
	h.db.Select("host_id, os_family, os_version").Where("host_id IN ?", hostIDs).Find(&hosts)
	type hostOS struct{ Family, Version string }
	osMap := make(map[string]hostOS, len(hosts))
	for _, host := range hosts {
		osMap[host.HostID] = hostOS{Family: host.OSFamily, Version: host.OSVersion}
	}

	username, _ := c.Get("username")
	createdBy, _ := username.(string)

	var tasks []model.RemediationTask
	for _, hv := range hostVulns {
		// 检查是否已有进行中的任务
		var existing int64
		h.db.Model(&model.RemediationTask{}).
			Where("vuln_id = ? AND host_id = ? AND status IN ?", vuln.ID, hv.HostID, []string{"pending", "confirmed", "running"}).
			Count(&existing)
		if existing > 0 {
			continue
		}

		// 根据主机 OS 选择正确的命令
		os := osMap[hv.HostID]
		cmd := selectCommandForHost(advice.Commands, os.Family, os.Version)

		task := model.RemediationTask{
			VulnID:       vuln.ID,
			CveID:        vuln.CveID,
			HostID:       hv.HostID,
			Hostname:     hv.Hostname,
			IP:           hv.IP,
			Component:    vuln.Component,
			FixedVersion: vuln.FixedVersion,
			Command:      cmd,
			Status:       "pending",
			CreatedBy:    createdBy,
		}
		tasks = append(tasks, task)
	}

	if len(tasks) == 0 {
		BadRequest(c, "所有指定主机已有进行中的修复任务")
		return
	}

	if err := h.db.Create(&tasks).Error; err != nil {
		h.logger.Error("创建修复任务失败", zap.Error(err))
		InternalError(c, "创建修复任务失败")
		return
	}

	Success(c, gin.H{
		"created": len(tasks),
		"tasks":   tasks,
	})
}

// ListTasks 查询修复任务列表
// GET /api/v1/remediation-tasks
func (h *RemediationTasksHandler) ListTasks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	status := c.Query("status")
	vulnID := c.Query("vuln_id")
	hostID := c.Query("host_id")

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	query := h.db.Model(&model.RemediationTask{})
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if vulnID != "" {
		query = query.Where("vuln_id = ?", vulnID)
	}
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}

	var total int64
	query.Count(&total)

	var tasks []model.RemediationTask
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&tasks).Error; err != nil {
		h.logger.Error("查询修复任务列表失败", zap.Error(err))
		InternalError(c, "查询修复任务列表失败")
		return
	}

	Success(c, gin.H{
		"total": total,
		"items": tasks,
	})
}

// GetTask 获取修复任务详情
// GET /api/v1/remediation-tasks/:id
func (h *RemediationTasksHandler) GetTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	var task model.RemediationTask
	if err := h.db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		InternalError(c, "查询任务失败")
		return
	}

	Success(c, task)
}

// ConfirmTask 用户确认执行修复任务
// POST /api/v1/remediation-tasks/:id/confirm
func (h *RemediationTasksHandler) ConfirmTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	var task model.RemediationTask
	if err := h.db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		InternalError(c, "查询任务失败")
		return
	}

	if task.Status != "pending" {
		BadRequest(c, "只有待确认状态的任务才能确认执行")
		return
	}

	// 可选：允许用户修改命令
	var req struct {
		Command string `json:"command"`
	}
	if err := c.ShouldBindJSON(&req); err == nil && req.Command != "" {
		task.Command = req.Command
	}

	username, _ := c.Get("username")
	confirmedBy, _ := username.(string)
	now := model.Now()

	if err := h.db.Model(&task).Updates(map[string]any{
		"status":       "confirmed",
		"confirmed_by": confirmedBy,
		"confirmed_at": now,
		"command":      task.Command,
	}).Error; err != nil {
		InternalError(c, "确认任务失败")
		return
	}

	SuccessMessage(c, "任务已确认，等待执行")
}

// CancelTask 取消修复任务
// POST /api/v1/remediation-tasks/:id/cancel
func (h *RemediationTasksHandler) CancelTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	var task model.RemediationTask
	if err := h.db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		InternalError(c, "查询任务失败")
		return
	}

	if task.Status != "pending" && task.Status != "confirmed" {
		BadRequest(c, "只有待确认或已确认状态的任务才能取消")
		return
	}

	if err := h.db.Model(&task).Update("status", "cancelled").Error; err != nil {
		InternalError(c, "取消任务失败")
		return
	}

	SuccessMessage(c, "任务已取消")
}

// BatchCreate 批量创建修复任务（按漏洞）
// POST /api/v1/remediation-tasks/batch
func (h *RemediationTasksHandler) BatchCreate(c *gin.Context) {
	var req struct {
		VulnIDs []uint `json:"vulnIds" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数无效：需要 vulnIds")
		return
	}

	username, _ := c.Get("username")
	createdBy, _ := username.(string)

	// 批量查询所有漏洞
	var vulns []model.Vulnerability
	h.db.Where("id IN ?", req.VulnIDs).Find(&vulns)
	vulnMap := make(map[uint]model.Vulnerability, len(vulns))
	for _, v := range vulns {
		vulnMap[v.ID] = v
	}

	// 批量查询所有相关 host_vulnerabilities
	var allHostVulns []model.HostVulnerability
	h.db.Where("vuln_id IN ? AND status = ?", req.VulnIDs, "unpatched").Find(&allHostVulns)
	hostVulnsByVuln := make(map[uint][]model.HostVulnerability)
	allHostIDs := make(map[string]struct{})
	for _, hv := range allHostVulns {
		hostVulnsByVuln[hv.VulnID] = append(hostVulnsByVuln[hv.VulnID], hv)
		allHostIDs[hv.HostID] = struct{}{}
	}

	// 批量查询所有主机 OS 信息
	hostIDList := make([]string, 0, len(allHostIDs))
	for id := range allHostIDs {
		hostIDList = append(hostIDList, id)
	}
	var hosts []model.Host
	if len(hostIDList) > 0 {
		h.db.Select("host_id, os_family, os_version").Where("host_id IN ?", hostIDList).Find(&hosts)
	}
	type hostOS struct{ Family, Version string }
	osMap := make(map[string]hostOS, len(hosts))
	for _, host := range hosts {
		osMap[host.HostID] = hostOS{Family: host.OSFamily, Version: host.OSVersion}
	}

	// 批量查询已有进行中的任务
	var existingTasks []model.RemediationTask
	h.db.Select("vuln_id, host_id").
		Where("vuln_id IN ? AND status IN ?", req.VulnIDs, []string{"pending", "confirmed", "running"}).
		Find(&existingTasks)
	existingSet := make(map[string]struct{}, len(existingTasks))
	for _, t := range existingTasks {
		existingSet[fmt.Sprintf("%d:%s", t.VulnID, t.HostID)] = struct{}{}
	}

	remSvc := biz.NewRemediationService(h.db, h.logger)
	var allTasks []model.RemediationTask
	vulnSet := make(map[uint]struct{})   // 去重统计涉及的漏洞
	hostSet := make(map[string]struct{}) // 去重统计涉及的主机
	skipped := 0

	for _, vulnID := range req.VulnIDs {
		vuln, ok := vulnMap[vulnID]
		if !ok {
			continue
		}
		hostVulns := hostVulnsByVuln[vulnID]
		if len(hostVulns) == 0 {
			continue
		}

		advice := remSvc.GetAdvice(&vuln)

		for _, hv := range hostVulns {
			key := fmt.Sprintf("%d:%s", vulnID, hv.HostID)
			if _, exists := existingSet[key]; exists {
				skipped++
				continue
			}

			os := osMap[hv.HostID]
			cmd := selectCommandForHost(advice.Commands, os.Family, os.Version)
			allTasks = append(allTasks, model.RemediationTask{
				VulnID:       vuln.ID,
				CveID:        vuln.CveID,
				HostID:       hv.HostID,
				Hostname:     hv.Hostname,
				IP:           hv.IP,
				Component:    vuln.Component,
				FixedVersion: vuln.FixedVersion,
				Command:      cmd,
				Status:       "pending",
				CreatedBy:    createdBy,
			})
			vulnSet[vulnID] = struct{}{}
			hostSet[hv.HostID] = struct{}{}
		}
	}

	totalCreated := 0
	if len(allTasks) > 0 {
		if err := h.db.Create(&allTasks).Error; err != nil {
			h.logger.Error("批量创建修复任务失败", zap.Error(err))
			InternalError(c, "批量创建修复任务失败")
			return
		}
		totalCreated = len(allTasks)
	}

	Success(c, gin.H{
		"created":   totalCreated,
		"vulnCount": len(vulnSet),
		"hostCount": len(hostSet),
		"skipped":   skipped,
	})
}

// RetryTask 重试失败的修复任务
// POST /api/v1/remediation-tasks/:id/retry
func (h *RemediationTasksHandler) RetryTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的任务 ID")
		return
	}

	var task model.RemediationTask
	if err := h.db.First(&task, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		InternalError(c, "查询任务失败")
		return
	}

	if task.Status != "failed" {
		BadRequest(c, "只有失败状态的任务才能重试")
		return
	}

	// 可选：允许用户修改命令
	var req struct {
		Command string `json:"command"`
	}
	if err := c.ShouldBindJSON(&req); err == nil && req.Command != "" {
		task.Command = req.Command
	}

	// 重置任务状态为 pending
	if err := h.db.Model(&task).Updates(map[string]any{
		"status":      "pending",
		"exec_output": "",
		"exit_code":   nil,
		"started_at":  nil,
		"finished_at": nil,
		"command":     task.Command,
	}).Error; err != nil {
		InternalError(c, "重试任务失败")
		return
	}

	SuccessMessage(c, "任务已重置为待确认状态")
}

// BatchConfirm 批量确认修复任务
// POST /api/v1/remediation-tasks/batch-confirm
func (h *RemediationTasksHandler) BatchConfirm(c *gin.Context) {
	var req struct {
		TaskIDs []uint `json:"taskIds" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数无效：需要 taskIds")
		return
	}

	username, _ := c.Get("username")
	confirmedBy, _ := username.(string)
	now := model.Now()

	var confirmed int
	for _, id := range req.TaskIDs {
		result := h.db.Model(&model.RemediationTask{}).
			Where("id = ? AND status = ?", id, "pending").
			Updates(map[string]any{
				"status":       "confirmed",
				"confirmed_by": confirmedBy,
				"confirmed_at": now,
			})
		if result.RowsAffected > 0 {
			confirmed++
		}
	}

	Success(c, gin.H{"confirmed": confirmed})
}

// BatchRetry 批量重试失败的修复任务
// POST /api/v1/remediation-tasks/batch-retry
func (h *RemediationTasksHandler) BatchRetry(c *gin.Context) {
	var req struct {
		TaskIDs []uint `json:"taskIds" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数无效：需要 taskIds")
		return
	}

	var retried int
	for _, id := range req.TaskIDs {
		result := h.db.Model(&model.RemediationTask{}).
			Where("id = ? AND status = ?", id, "failed").
			Updates(map[string]any{
				"status":      "pending",
				"exec_output": "",
				"exit_code":   nil,
				"started_at":  nil,
				"finished_at": nil,
			})
		if result.RowsAffected > 0 {
			retried++
		}
	}

	Success(c, gin.H{"retried": retried})
}

// BatchCancel 批量取消修复任务
// POST /api/v1/remediation-tasks/batch-cancel
func (h *RemediationTasksHandler) BatchCancel(c *gin.Context) {
	var req struct {
		TaskIDs []uint `json:"taskIds" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数无效：需要 taskIds")
		return
	}

	var cancelled int
	for _, id := range req.TaskIDs {
		result := h.db.Model(&model.RemediationTask{}).
			Where("id = ? AND status IN ?", id, []string{"pending", "confirmed"}).
			Update("status", "cancelled")
		if result.RowsAffected > 0 {
			cancelled++
		}
	}

	Success(c, gin.H{"cancelled": cancelled})
}

// GetTaskStats 获取修复任务统计
// GET /api/v1/remediation-tasks/stats
func (h *RemediationTasksHandler) GetTaskStats(c *gin.Context) {
	type statusCount struct {
		Status string `gorm:"column:status"`
		Count  int64  `gorm:"column:count"`
	}
	var rows []statusCount
	h.db.Model(&model.RemediationTask{}).
		Select("status, COUNT(*) as count").
		Group("status").
		Scan(&rows)

	result := map[string]int64{
		"pending":   0,
		"confirmed": 0,
		"running":   0,
		"success":   0,
		"failed":    0,
		"cancelled": 0,
	}
	var total int64
	for _, r := range rows {
		result[r.Status] = r.Count
		total += r.Count
	}
	result["total"] = total

	// 今日完成数
	var todaySuccess int64
	h.db.Model(&model.RemediationTask{}).
		Where("status = ? AND finished_at >= ?", "success", time.Now().Format("2006-01-02")).
		Count(&todaySuccess)
	result["todaySuccess"] = todaySuccess

	Success(c, result)
}
