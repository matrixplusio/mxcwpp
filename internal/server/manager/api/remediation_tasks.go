package api

import (
	"encoding/json"
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

// precheckPackage agent 上报的 precheck_packages JSON 元素
type precheckPackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installed_version"`
	AvailableVersion string `json:"available_version"`
	Repo             string `json:"repo"`
	Action           string `json:"action"`
}

// buildCommandFromPreCheck 优先用 agent pre-check 已确认的真实包名生成命令。
// 返回 "" 表示 precheck 不可用 / 无 upgradable 包，应 fallback 老逻辑。
//
// 例：vuln.component="openssl"，主机实际装了 openssl + openssl-libs，
// pre-check 命中 → cmd = "dnf upgrade openssl openssl-libs -y"
// 而非以前的 "dnf upgrade openssl-1.1.1g-15 -y"（fixed_version 拼错）。
func buildCommandFromPreCheck(hv *model.HostVulnerability, osFamily, osVersion string) string {
	if hv.PreCheckStatus != model.PreCheckStatusAvailable &&
		hv.PreCheckStatus != model.PreCheckStatusAvailableEPEL {
		return ""
	}
	if hv.PreCheckPackages == "" {
		return ""
	}
	var pkgs []precheckPackage
	if err := json.Unmarshal([]byte(hv.PreCheckPackages), &pkgs); err != nil {
		return ""
	}
	var names []string
	for _, p := range pkgs {
		if p.Action == "upgrade" && p.Name != "" {
			names = append(names, p.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	pkgMgr := detectPackageManager(osFamily, osVersion)
	pkgList := strings.Join(names, " ")
	switch pkgMgr {
	case "rpm-dnf":
		if hv.PreCheckStatus == model.PreCheckStatusAvailableEPEL {
			return fmt.Sprintf("dnf upgrade --enablerepo=epel %s -y", pkgList)
		}
		return fmt.Sprintf("dnf upgrade %s -y", pkgList)
	case "rpm-yum":
		if hv.PreCheckStatus == model.PreCheckStatusAvailableEPEL {
			return fmt.Sprintf("yum update --enablerepo=epel %s -y", pkgList)
		}
		return fmt.Sprintf("yum update %s -y", pkgList)
	case "deb":
		return fmt.Sprintf("apt-get install --only-upgrade %s -y", pkgList)
	}
	return ""
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
	skippedNotApplicable := 0
	skippedNoCommand := 0
	for _, hv := range hostVulns {
		os := osMap[hv.HostID]
		// P0 fix: vuln source 必须适用于 host OS family（防 Debian 包给 CentOS）
		if !biz.VulnApplicableToHost(vuln.Source, os.Family) {
			skippedNotApplicable++
			continue
		}
		// 检查是否已有进行中的任务
		var existing int64
		h.db.Model(&model.RemediationTask{}).
			Where("vuln_id = ? AND host_id = ? AND status IN ?", vuln.ID, hv.HostID, []string{"pending", "confirmed", "running"}).
			Count(&existing)
		if existing > 0 {
			continue
		}

		// P1.4: 优先用 agent pre-check 已确认的真实包名生成命令（精确）；否则 fallback
		cmd := buildCommandFromPreCheck(&hv, os.Family, os.Version)
		if cmd == "" {
			cmd = selectCommandForHost(advice.Commands, os.Family, os.Version)
		}
		if cmd == "" {
			skippedNoCommand++
			continue
		}

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
		BadRequest(c, fmt.Sprintf("无可创建：OS 不适用 %d，无命令 %d，其余已有进行中", skippedNotApplicable, skippedNoCommand))
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
			// P0 fix: vuln source 必须适用于 host OS family（防 Debian 包给 CentOS）
			if !biz.VulnApplicableToHost(vuln.Source, os.Family) {
				skipped++
				continue
			}

			// P1.4: 优先用 agent pre-check 已确认的真实包名
			cmd := buildCommandFromPreCheck(&hv, os.Family, os.Version)
			if cmd == "" {
				cmd = selectCommandForHost(advice.Commands, os.Family, os.Version)
			}
			if cmd == "" {
				skipped++
				continue
			}
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

// CreateForHost 单 host 批量创建修复任务
// POST /api/v1/remediation-tasks/host-batch
// body: {hostId, vulnIds?: [], allUnpatched?: bool}
//   - vulnIds 模式：为指定 host 的子集 vuln 创建任务
//   - allUnpatched 模式：为指定 host 的全部 unpatched vuln 创建任务（忽略 vulnIds）
func (h *RemediationTasksHandler) CreateForHost(c *gin.Context) {
	var req struct {
		HostID       string `json:"hostId" binding:"required"`
		VulnIDs      []uint `json:"vulnIds"`
		AllUnpatched bool   `json:"allUnpatched"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数无效：需要 hostId")
		return
	}
	if !req.AllUnpatched && len(req.VulnIDs) == 0 {
		BadRequest(c, "需指定 vulnIds 或 allUnpatched=true")
		return
	}

	// 校验 host 存在，并拿 OS 信息选包管理器命令
	var host model.Host
	if err := h.db.Select("host_id, os_family, os_version, hostname").
		Where("host_id = ?", req.HostID).First(&host).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "host 不存在")
			return
		}
		h.logger.Error("查询 host 失败", zap.Error(err))
		InternalError(c, "查询 host 失败")
		return
	}

	// 拉该 host unpatched host_vulnerabilities，按需 vulnIds 子集过滤
	query := h.db.Where("host_id = ? AND status = ?", req.HostID, "unpatched")
	if !req.AllUnpatched {
		query = query.Where("vuln_id IN ?", req.VulnIDs)
	}
	var hostVulns []model.HostVulnerability
	if err := query.Find(&hostVulns).Error; err != nil {
		h.logger.Error("查询主机漏洞失败", zap.Error(err))
		InternalError(c, "查询主机漏洞失败")
		return
	}
	if len(hostVulns) == 0 {
		BadRequest(c, "该主机无匹配的未修复漏洞")
		return
	}

	vulnIDs := make([]uint, 0, len(hostVulns))
	for _, hv := range hostVulns {
		vulnIDs = append(vulnIDs, hv.VulnID)
	}
	var vulns []model.Vulnerability
	h.db.Where("id IN ?", vulnIDs).Find(&vulns)
	vulnMap := make(map[uint]model.Vulnerability, len(vulns))
	for _, v := range vulns {
		vulnMap[v.ID] = v
	}

	// 跳过已有进行中（pending/confirmed/running）的任务，避免重复
	var existing []model.RemediationTask
	h.db.Select("vuln_id").
		Where("host_id = ? AND vuln_id IN ? AND status IN ?",
			req.HostID, vulnIDs, []string{"pending", "confirmed", "running"}).
		Find(&existing)
	existingSet := make(map[uint]struct{}, len(existing))
	for _, t := range existing {
		existingSet[t.VulnID] = struct{}{}
	}

	username, _ := c.Get("username")
	createdBy, _ := username.(string)

	remSvc := biz.NewRemediationService(h.db, h.logger)
	var tasks []model.RemediationTask
	skipped := 0
	skippedNotApplicable := 0 // vuln source 与 host OS family 不匹配（Debian 包给 CentOS）
	skippedNoCommand := 0     // 无可执行命令（包管理器未识别且 fixed_version 无效）
	for _, hv := range hostVulns {
		if _, exists := existingSet[hv.VulnID]; exists {
			skipped++
			continue
		}
		v, ok := vulnMap[hv.VulnID]
		if !ok {
			skipped++
			continue
		}
		// P0 fix: vuln source 必须适用于 host OS family，否则跳过（防 Debian 包给 CentOS）
		if !biz.VulnApplicableToHost(v.Source, host.OSFamily) {
			skippedNotApplicable++
			continue
		}
		// P1.4: 优先用 agent pre-check 真实包名
		cmd := buildCommandFromPreCheck(&hv, host.OSFamily, host.OSVersion)
		if cmd == "" {
			advice := remSvc.GetAdvice(&v)
			cmd = selectCommandForHost(advice.Commands, host.OSFamily, host.OSVersion)
		}
		if cmd == "" {
			skippedNoCommand++
			continue
		}
		tasks = append(tasks, model.RemediationTask{
			VulnID:       v.ID,
			CveID:        v.CveID,
			HostID:       hv.HostID,
			Hostname:     hv.Hostname,
			IP:           hv.IP,
			Component:    v.Component,
			FixedVersion: v.FixedVersion,
			Command:      cmd,
			Status:       "pending",
			CreatedBy:    createdBy,
		})
	}

	if len(tasks) == 0 {
		BadRequest(c, fmt.Sprintf(
			"无可创建的任务：已存在 %d，OS 不适用 %d，无命令 %d",
			skipped, skippedNotApplicable, skippedNoCommand))
		return
	}

	if err := h.db.Create(&tasks).Error; err != nil {
		h.logger.Error("批量创建主机修复任务失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	Success(c, gin.H{
		"created":              len(tasks),
		"skipped":              skipped,
		"skippedNotApplicable": skippedNotApplicable,
		"skippedNoCommand":     skippedNoCommand,
		"hostId":               req.HostID,
		"hostname":             host.Hostname,
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
