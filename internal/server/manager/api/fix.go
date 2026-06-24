package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/service"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// FixHandler 是基线修复 API 处理器
type FixHandler struct {
	db            *gorm.DB
	logger        *zap.Logger
	taskService   *service.TaskService
	policyService *service.PolicyService
	acDispatcher  *sd.ACDispatcher
}

// NewFixHandler 创建修复处理器
func NewFixHandler(db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) *FixHandler {
	return &FixHandler{
		db:            db,
		logger:        logger,
		taskService:   service.NewTaskService(db, logger),
		policyService: service.NewPolicyService(db, logger),
		acDispatcher:  acDispatcher,
	}
}

// FixableItemResponse 可修复项响应
type FixableItemResponse struct {
	TaskID        string `json:"task_id"`
	HostID        string `json:"host_id"`
	Hostname      string `json:"hostname"`
	IP            string `json:"ip"`
	BusinessLine  string `json:"business_line"`
	RuleID        string `json:"rule_id"`
	Title         string `json:"title"`
	Category      string `json:"category"`
	Severity      string `json:"severity"`
	FixSuggestion string `json:"fix_suggestion"`
	FixCommand    string `json:"fix_command"`
	Actual        string `json:"actual"`
	Expected      string `json:"expected"`
	HasFix        bool   `json:"has_fix"`
}

// GetFixableItems 获取可修复项列表
func (h *FixHandler) GetFixableItems(c *gin.Context) {
	// 解析查询参数
	hostIDsStr := c.QueryArray("host_ids[]")
	severitiesStr := c.QueryArray("severities[]")
	businessLine := c.Query("business_line")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	// 构建查询
	query := h.db.Model(&model.ScanResult{}).
		Where("scan_results.status IN ?", []string{"fail", "error"})

	// 主机筛选
	if len(hostIDsStr) > 0 {
		query = query.Where("scan_results.host_id IN ?", hostIDsStr)
	}

	// 严重级别筛选
	if len(severitiesStr) > 0 {
		query = query.Where("scan_results.severity IN ?", severitiesStr)
	}

	// 业务线筛选：需要通过 JOIN hosts 表来筛选
	if businessLine != "" {
		query = query.Joins("JOIN hosts ON scan_results.host_id = hosts.host_id").
			Where("hosts.business_line = ?", businessLine)
	}

	// 查询总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询可修复项总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 分页查询
	var results []model.ScanResult
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).
		Order("severity DESC, checked_at DESC").
		Find(&results).Error; err != nil {
		h.logger.Error("查询可修复项失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 获取主机信息
	hostIDs := make([]string, 0, len(results))
	for _, r := range results {
		hostIDs = append(hostIDs, r.HostID)
	}
	var hosts []model.Host
	if len(hostIDs) > 0 {
		h.db.Where("host_id IN ?", hostIDs).Find(&hosts)
	}
	type HostInfo struct {
		Hostname     string
		IP           string
		BusinessLine string
	}
	hostMap := make(map[string]HostInfo)
	for _, host := range hosts {
		ip := ""
		if len(host.IPv4) > 0 {
			ip = host.IPv4[0] // 使用第一个 IPv4 地址
		}
		hostMap[host.HostID] = HostInfo{
			Hostname:     host.Hostname,
			IP:           ip,
			BusinessLine: host.BusinessLine,
		}
	}

	// 获取规则信息（包含修复命令）
	ruleIDs := make([]string, 0, len(results))
	for _, r := range results {
		ruleIDs = append(ruleIDs, r.RuleID)
	}
	var rules []model.Rule
	if len(ruleIDs) > 0 {
		h.db.Where("rule_id IN ?", ruleIDs).Find(&rules)
	}
	ruleMap := make(map[string]*model.Rule)
	for i := range rules {
		ruleMap[rules[i].RuleID] = &rules[i]
	}

	// 构建响应
	items := make([]FixableItemResponse, 0, len(results))
	for _, r := range results {
		rule := ruleMap[r.RuleID]
		hostInfo := hostMap[r.HostID]
		item := FixableItemResponse{
			TaskID:        r.TaskID,
			HostID:        r.HostID,
			Hostname:      hostInfo.Hostname,
			IP:            hostInfo.IP,
			BusinessLine:  hostInfo.BusinessLine,
			RuleID:        r.RuleID,
			Title:         r.Title,
			Category:      r.Category,
			Severity:      r.Severity,
			FixSuggestion: r.FixSuggestion,
			Actual:        r.Actual,
			Expected:      r.Expected,
			HasFix:        false,
		}

		// 检查是否有修复命令
		if rule != nil && rule.FixConfig.Command != "" {
			item.HasFix = true
			item.FixCommand = rule.FixConfig.Command
		}

		items = append(items, item)
	}

	Success(c, gin.H{
		"items": items,
		"total": total,
	})
}

// ScanResultKey 标识一条扫描结果的复合键
type ScanResultKey struct {
	TaskID string `json:"task_id"`
	HostID string `json:"host_id"`
	RuleID string `json:"rule_id"`
}

// CreateFixTaskRequest 创建修复任务请求
type CreateFixTaskRequest struct {
	// 方式1：直接指定扫描结果的复合键（推荐，精确指定要修复的项）
	ResultKeys []ScanResultKey `json:"result_keys"`

	// 方式2：指定主机和规则ID
	HostIDs    []string `json:"host_ids"`
	RuleIDs    []string `json:"rule_ids"`
	Severities []string `json:"severities"`

	// 方式3：使用筛选条件（用于全选所有筛选结果）
	UseFilters   bool   `json:"use_filters"`
	BusinessLine string `json:"business_line"`
}

// CreateFixTask 创建修复任务
func (h *FixHandler) CreateFixTask(c *gin.Context) {
	var req CreateFixTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	var hostIDs, ruleIDs []string
	var actualCount int64

	if req.UseFilters {
		// 方式3：使用筛选条件查询所有符合条件的失败记录
		h.logger.Info("使用筛选条件创建修复任务",
			zap.String("business_line", req.BusinessLine),
			zap.Strings("severities", req.Severities))

		// 构建查询
		query := h.db.Model(&model.ScanResult{}).
			Where("scan_results.status IN ?", []string{"fail", "error"})

		// 严重级别筛选
		if len(req.Severities) > 0 {
			query = query.Where("scan_results.severity IN ?", req.Severities)
		}

		// 业务线筛选：需要通过 JOIN hosts 表来筛选
		if req.BusinessLine != "" {
			query = query.Joins("JOIN hosts ON scan_results.host_id = hosts.host_id").
				Where("hosts.business_line = ?", req.BusinessLine)
		}

		// 查询所有符合条件的记录
		var results []model.ScanResult
		if err := query.Find(&results).Error; err != nil {
			h.logger.Error("查询失败记录失败", zap.Error(err))
			InternalError(c, "查询失败")
			return
		}

		if len(results) == 0 {
			BadRequest(c, "没有符合条件的失败记录")
			return
		}

		// 提取唯一的 host_ids 和 rule_ids
		hostIDSet := make(map[string]bool)
		ruleIDSet := make(map[string]bool)
		for _, r := range results {
			hostIDSet[r.HostID] = true
			ruleIDSet[r.RuleID] = true
		}

		hostIDs = make([]string, 0, len(hostIDSet))
		for id := range hostIDSet {
			hostIDs = append(hostIDs, id)
		}

		ruleIDs = make([]string, 0, len(ruleIDSet))
		for id := range ruleIDSet {
			ruleIDs = append(ruleIDs, id)
		}

		actualCount = int64(len(results))

		h.logger.Info("筛选条件查询结果",
			zap.Int("total_records", len(results)),
			zap.Int("unique_hosts", len(hostIDs)),
			zap.Int("unique_rules", len(ruleIDs)))

	} else if len(req.ResultKeys) > 0 {
		// 方式1：使用复合键（推荐方式，精确指定要修复的项）
		h.logger.Info("使用 result_keys 创建修复任务",
			zap.Int("key_count", len(req.ResultKeys)))

		// 构建查询条件：(task_id, host_id, rule_id) 组合
		var results []model.ScanResult
		query := h.db.Where("status IN ?", []string{"fail", "error"})
		for i, key := range req.ResultKeys {
			if i == 0 {
				query = query.Where("(task_id = ? AND host_id = ? AND rule_id = ?)", key.TaskID, key.HostID, key.RuleID)
			} else {
				query = query.Or("(task_id = ? AND host_id = ? AND rule_id = ?) AND status IN ?", key.TaskID, key.HostID, key.RuleID, []string{"fail", "error"})
			}
		}
		if err := query.Find(&results).Error; err != nil {
			h.logger.Error("查询失败记录失败", zap.Error(err))
			InternalError(c, "查询失败")
			return
		}

		if len(results) == 0 {
			BadRequest(c, "没有找到符合条件的失败记录")
			return
		}

		// 提取唯一的 host_ids 和 rule_ids
		hostIDSet := make(map[string]bool)
		ruleIDSet := make(map[string]bool)
		for _, r := range results {
			hostIDSet[r.HostID] = true
			ruleIDSet[r.RuleID] = true
		}

		hostIDs = make([]string, 0, len(hostIDSet))
		for id := range hostIDSet {
			hostIDs = append(hostIDs, id)
		}

		ruleIDs = make([]string, 0, len(ruleIDSet))
		for id := range ruleIDSet {
			ruleIDs = append(ruleIDs, id)
		}

		actualCount = int64(len(results))

		h.logger.Info("result_keys 查询结果",
			zap.Int("total_records", len(results)),
			zap.Int("unique_hosts", len(hostIDs)),
			zap.Int("unique_rules", len(ruleIDs)))

	} else {
		// 方式2：直接使用指定的主机和规则ID（已废弃，会导致统计不准确）
		if len(req.HostIDs) == 0 {
			BadRequest(c, "主机列表不能为空")
			return
		}
		if len(req.RuleIDs) == 0 {
			BadRequest(c, "规则列表不能为空")
			return
		}

		h.logger.Warn("使用 host_ids + rule_ids 创建修复任务（已废弃，可能导致统计不准确）",
			zap.Int("host_count", len(req.HostIDs)),
			zap.Int("rule_count", len(req.RuleIDs)))

		hostIDs = req.HostIDs
		ruleIDs = req.RuleIDs

		// 查询实际需要修复的项数（只统计失败的记录）
		h.db.Model(&model.ScanResult{}).
			Where("host_id IN ?", hostIDs).
			Where("rule_id IN ?", ruleIDs).
			Where("status IN ?", []string{"fail", "error"}).
			Count(&actualCount)
	}

	// 创建任务
	taskID := uuid.New().String()

	// 如果没有查询到失败记录，使用主机数×规则数作为默认值
	totalCount := int(actualCount)
	if totalCount == 0 {
		totalCount = len(hostIDs) * len(ruleIDs)
	}

	task := &model.FixTask{
		TaskID:       taskID,
		HostIDs:      hostIDs,
		RuleIDs:      ruleIDs,
		Severities:   req.Severities,
		Status:       model.FixTaskStatusPending,
		TotalCount:   totalCount,
		SuccessCount: 0,
		FailedCount:  0,
		Progress:     0,
		CreatedBy:    c.GetString("user_id"),
		CreatedAt:    model.Now(),
	}

	if err := h.db.Create(task).Error; err != nil {
		h.logger.Error("创建修复任务失败", zap.Error(err))
		InternalError(c, "创建任务失败")
		return
	}

	// 修复任务将由调度器自动分发到 Agent
	// 调度器会定期检查 pending 状态的修复任务并下发

	h.logger.Info("创建修复任务成功",
		zap.String("task_id", taskID),
		zap.Int("host_count", len(hostIDs)),
		zap.Int("rule_count", len(ruleIDs)),
		zap.Int("total_count", totalCount))

	Success(c, gin.H{
		"task_id": taskID,
	})
}

// GetFixTask 获取修复任务详情
func (h *FixHandler) GetFixTask(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		BadRequest(c, "任务ID不能为空")
		return
	}

	var task model.FixTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询修复任务失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, task)
}

// ListFixTasks 获取修复任务列表
func (h *FixHandler) ListFixTasks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	status := c.Query("status")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	query := h.db.Model(&model.FixTask{})

	// 状态筛选
	if status != "" {
		query = query.Where("status = ?", status)
	}

	// 查询总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询修复任务总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 分页查询
	var tasks []model.FixTask
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).
		Order("created_at DESC").
		Find(&tasks).Error; err != nil {
		h.logger.Error("查询修复任务列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, gin.H{
		"items": tasks,
		"total": total,
	})
}

// FixResultResponse 修复结果响应
type FixResultResponse struct {
	model.FixResult
	Hostname string `json:"hostname"`
	Title    string `json:"title"`
}

// GetFixResults 获取修复结果
func (h *FixHandler) GetFixResults(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		BadRequest(c, "任务ID不能为空")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	status := c.Query("status")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	query := h.db.Model(&model.FixResult{}).Where("task_id = ?", taskID)

	// 状态筛选
	if status != "" {
		query = query.Where("status = ?", status)
	}

	// 查询总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询修复结果总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 分页查询
	var results []model.FixResult
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).
		Order("fixed_at DESC").
		Find(&results).Error; err != nil {
		h.logger.Error("查询修复结果失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 获取主机信息
	hostIDs := make([]string, 0, len(results))
	for _, r := range results {
		hostIDs = append(hostIDs, r.HostID)
	}
	var hosts []model.Host
	if len(hostIDs) > 0 {
		h.db.Where("host_id IN ?", hostIDs).Find(&hosts)
	}
	hostMap := make(map[string]string)
	for _, host := range hosts {
		hostMap[host.HostID] = host.Hostname
	}

	// 获取规则标题
	ruleIDs := make([]string, 0, len(results))
	for _, r := range results {
		ruleIDs = append(ruleIDs, r.RuleID)
	}
	var rules []model.Rule
	if len(ruleIDs) > 0 {
		h.db.Where("rule_id IN ?", ruleIDs).Find(&rules)
	}
	ruleMap := make(map[string]string)
	for _, rule := range rules {
		ruleMap[rule.RuleID] = rule.Title
	}

	// 构建响应
	items := make([]FixResultResponse, 0, len(results))
	for _, r := range results {
		items = append(items, FixResultResponse{
			FixResult: r,
			Hostname:  hostMap[r.HostID],
			Title:     ruleMap[r.RuleID],
		})
	}

	Success(c, gin.H{
		"items": items,
		"total": total,
	})
}

// CancelFixTask 取消修复任务
func (h *FixHandler) CancelFixTask(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		BadRequest(c, "任务ID不能为空")
		return
	}

	var task model.FixTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询修复任务失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 只能取消待执行或执行中的任务
	if task.Status != model.FixTaskStatusPending && task.Status != model.FixTaskStatusRunning {
		BadRequest(c, fmt.Sprintf("任务状态为 %s，无法取消", task.Status))
		return
	}

	// CAS：仅当状态仍为原值时更新
	result := h.db.Model(&model.FixTask{}).
		Where("task_id = ? AND status = ?", taskID, task.Status).
		Updates(map[string]interface{}{
			"status":       model.FixTaskStatusFailed,
			"completed_at": model.Now(),
		})
	if result.Error != nil {
		h.logger.Error("取消修复任务失败", zap.Error(result.Error))
		InternalError(c, "取消任务失败")
		return
	}
	if result.RowsAffected == 0 {
		Conflict(c, "任务状态已变更，请刷新后重试")
		return
	}

	// 向 Agent 发送取消信号（尽力而为）
	if task.Status == model.FixTaskStatusRunning && h.acDispatcher != nil {
		go func() {
			var hostStatuses []model.FixTaskHostStatus
			if err := h.db.Where("task_id = ? AND status = ?", taskID, model.FixTaskHostStatusDispatched).
				Find(&hostStatuses).Error; err != nil {
				return
			}
			cancelCmd := &grpcProto.Command{
				Tasks: []*grpcProto.Task{{
					DataType:   9900,
					ObjectName: "baseline",
					Token:      taskID,
				}},
			}
			for _, hs := range hostStatuses {
				_ = h.acDispatcher.SendCommand(hs.HostID, cancelCmd)
			}
		}()
	}

	h.logger.Info("取消修复任务成功", zap.String("task_id", taskID))
	Success(c, nil)
}

// DeleteFixTask 删除修复任务
func (h *FixHandler) DeleteFixTask(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		BadRequest(c, "任务ID不能为空")
		return
	}

	var task model.FixTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询修复任务失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 只能删除已完成或失败的任务
	if task.Status == model.FixTaskStatusRunning {
		BadRequest(c, "执行中的任务无法删除")
		return
	}

	// 删除任务和相关结果
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		// 删除修复结果
		if err := tx.Where("task_id = ?", taskID).Delete(&model.FixResult{}).Error; err != nil {
			return err
		}
		// 删除任务
		if err := tx.Delete(&task).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		h.logger.Error("删除修复任务失败", zap.Error(err))
		InternalError(c, "删除任务失败")
		return
	}

	h.logger.Info("删除修复任务成功", zap.String("task_id", taskID))
	Success(c, nil)
}

// GetFixTaskHostStatus 获取修复任务主机状态列表
func (h *FixHandler) GetFixTaskHostStatus(c *gin.Context) {
	taskID := c.Param("task_id")
	if taskID == "" {
		BadRequest(c, "任务ID不能为空")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	status := c.Query("status")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	query := h.db.Model(&model.FixTaskHostStatus{}).Where("task_id = ?", taskID)

	// 状态筛选
	if status != "" {
		query = query.Where("status = ?", status)
	}

	// 查询总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询修复任务主机状态总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	// 分页查询
	var hostStatuses []model.FixTaskHostStatus
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).
		Order("dispatched_at DESC").
		Find(&hostStatuses).Error; err != nil {
		h.logger.Error("查询修复任务主机状态失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, gin.H{
		"items": hostStatuses,
		"total": total,
	})
}
