// Package api 提供 HTTP API 处理器
package api

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/agentcenter/service"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TasksHandler 是任务管理 API 处理器
type TasksHandler struct {
	taskService   *service.TaskService
	policyService *service.PolicyService
	db            *gorm.DB
	logger        *zap.Logger
	acDispatcher  *sd.ACDispatcher // 用于向 Agent 发送取消命令
}

// NewTasksHandler 创建任务处理器
func NewTasksHandler(db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) *TasksHandler {
	return &TasksHandler{
		taskService:   service.NewTaskService(db, logger),
		policyService: service.NewPolicyService(db, logger),
		db:            db,
		logger:        logger,
		acDispatcher:  acDispatcher,
	}
}

// CreateTaskRequest 创建任务请求
type CreateTaskRequest struct {
	Name      string                 `json:"name" binding:"required"`
	Type      string                 `json:"type" binding:"required"`
	Targets   map[string]interface{} `json:"targets" binding:"required"`
	PolicyID  string                 `json:"policy_id"`  // 兼容旧版本：单策略
	PolicyIDs []string               `json:"policy_ids"` // 新版本：多策略
	RuleIDs   []string               `json:"rule_ids"`
	Schedule  map[string]interface{} `json:"schedule"`
}

// TaskResponse 任务响应（包含计算字段）
type TaskResponse struct {
	model.ScanTask
	TargetHosts        []string `json:"target_hosts"`         // 目标主机 ID 列表
	MatchedHostCount   int      `json:"matched_host_count"`   // 匹配的主机数量（在线）
	TotalHostCount     int      `json:"total_host_count"`     // 总目标主机数量（包括离线）
	TotalRuleCount     int      `json:"total_rule_count"`     // 关联策略的规则总数
	ExpectedCheckCount int      `json:"expected_check_count"` // 预期检查项总数（在线主机数 × 规则数）
}

// enrichTaskWithTargetHosts 为任务添加目标主机信息
func (h *TasksHandler) enrichTaskWithTargetHosts(task *model.ScanTask) *TaskResponse {
	response := &TaskResponse{
		ScanTask:    *task,
		TargetHosts: []string{},
	}

	var hosts []model.Host
	var totalHosts []model.Host

	// 构建运行时类型筛选条件
	runtimeType := task.TargetConfig.RuntimeType
	baseQuery := h.db.Model(&model.Host{})
	onlineQuery := h.db.Model(&model.Host{}).Where("status = ?", model.HostStatusOnline)

	// 如果指定了运行时类型，添加筛选条件
	if runtimeType != "" {
		if runtimeType == model.RuntimeTypeVM {
			// 虚拟机：runtime_type = 'vm' 或为空（兼容旧数据）
			baseQuery = baseQuery.Where("(runtime_type = ? OR runtime_type = '' OR runtime_type IS NULL)", model.RuntimeTypeVM)
			onlineQuery = onlineQuery.Where("(runtime_type = ? OR runtime_type = '' OR runtime_type IS NULL)", model.RuntimeTypeVM)
		} else {
			baseQuery = baseQuery.Where("runtime_type = ?", runtimeType)
			onlineQuery = onlineQuery.Where("runtime_type = ?", runtimeType)
		}
	}

	switch task.TargetType {
	case model.TargetTypeAll:
		// 查询所有主机
		baseQuery.Find(&totalHosts)
		onlineQuery.Find(&hosts)
		for _, host := range totalHosts {
			response.TargetHosts = append(response.TargetHosts, host.HostID)
		}

	case model.TargetTypeHostIDs:
		// 使用指定的主机 ID
		if len(task.TargetConfig.HostIDs) > 0 {
			response.TargetHosts = task.TargetConfig.HostIDs
			baseQuery.Where("host_id IN ?", task.TargetConfig.HostIDs).Find(&totalHosts)
			onlineQuery.Where("host_id IN ?", task.TargetConfig.HostIDs).Find(&hosts)
		}

	case model.TargetTypeOSFamily:
		// 查询指定 OS 系列的主机
		if len(task.TargetConfig.OSFamily) > 0 {
			baseQuery.Where("os_family IN ?", task.TargetConfig.OSFamily).Find(&totalHosts)
			onlineQuery.Where("os_family IN ?", task.TargetConfig.OSFamily).Find(&hosts)
			for _, host := range totalHosts {
				response.TargetHosts = append(response.TargetHosts, host.HostID)
			}
		}
	}

	response.MatchedHostCount = len(hosts)
	response.TotalHostCount = len(totalHosts)

	// 计算关联策略的规则总数
	policyIDs := task.GetPolicyIDs()
	if len(policyIDs) > 0 {
		var ruleCount int64
		h.db.Model(&model.Rule{}).Where("policy_id IN ? AND enabled = ?", policyIDs, true).Count(&ruleCount)
		response.TotalRuleCount = int(ruleCount)

		// 预期检查项总数：
		// - 已下发的任务（running/completed/failed）：使用实际下发主机数
		// - 未下发的任务（created/pending）：使用当前在线主机数作为预估
		hostCountForExpected := response.MatchedHostCount
		if task.DispatchedHostCount > 0 {
			hostCountForExpected = task.DispatchedHostCount
		}
		response.ExpectedCheckCount = hostCountForExpected * response.TotalRuleCount
	}

	return response
}

// CreateTask 创建扫描任务
// POST /api/v1/tasks
func (h *TasksHandler) CreateTask(c *gin.Context) {
	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	// 获取策略ID列表（兼容新旧版本）
	policyIDs := req.PolicyIDs
	if len(policyIDs) == 0 && req.PolicyID != "" {
		policyIDs = []string{req.PolicyID}
	}
	if len(policyIDs) == 0 {
		BadRequest(c, "请至少指定一个策略 (policy_id 或 policy_ids)")
		return
	}

	// 验证所有策略是否存在
	for _, policyID := range policyIDs {
		_, err := h.policyService.GetPolicy(policyID)
		if err != nil {
			if strings.Contains(err.Error(), "不存在") {
				NotFound(c, "策略不存在: "+policyID)
				return
			}
			h.logger.Error("查询策略失败", zap.String("policy_id", policyID), zap.Error(err))
			InternalError(c, "查询策略失败")
			return
		}
	}

	// 解析目标配置
	targetType, ok := req.Targets["type"].(string)
	if !ok {
		BadRequest(c, "targets.type 必须为字符串")
		return
	}

	var targetConfig model.TargetConfig

	// 解析运行时类型（可选）
	if runtimeType, ok := req.Targets["runtime_type"].(string); ok && runtimeType != "" {
		targetConfig.RuntimeType = model.RuntimeType(runtimeType)
	}

	switch targetType {
	case "all":
		// 不需要额外配置
	case "host_ids":
		hostIDsInterface, ok := req.Targets["host_ids"].([]interface{})
		if !ok {
			BadRequest(c, "targets.host_ids 必须为数组")
			return
		}
		hostIDs := make([]string, 0, len(hostIDsInterface))
		for _, id := range hostIDsInterface {
			if idStr, ok := id.(string); ok {
				hostIDs = append(hostIDs, idStr)
			}
		}
		targetConfig.HostIDs = hostIDs
	case "os_family":
		osFamilyInterface, ok := req.Targets["os_family"].([]interface{})
		if !ok {
			BadRequest(c, "targets.os_family 必须为数组")
			return
		}
		osFamily := make([]string, 0, len(osFamilyInterface))
		for _, os := range osFamilyInterface {
			if osStr, ok := os.(string); ok {
				osFamily = append(osFamily, osStr)
			}
		}
		targetConfig.OSFamily = osFamily
	default:
		BadRequest(c, "无效的 target_type: "+targetType)
		return
	}

	// 创建任务（状态为 created，等待用户确认执行）
	task := &model.ScanTask{
		TaskID:       uuid.New().String(),
		Name:         req.Name,
		Type:         model.TaskType(req.Type),
		TargetType:   model.TargetType(targetType),
		TargetConfig: targetConfig,
		PolicyID:     policyIDs[0],                 // 兼容旧版本
		PolicyIDs:    model.StringArray(policyIDs), // 新版本多策略
		RuleIDs:      model.StringArray(req.RuleIDs),
		Status:       model.TaskStatusCreated,
	}

	if err := h.db.Create(task).Error; err != nil {
		h.logger.Error("创建任务失败", zap.Error(err))
		InternalError(c, "创建任务失败")
		return
	}

	h.logger.Info("任务已创建", zap.String("task_id", task.TaskID))

	Created(c, h.enrichTaskWithTargetHosts(task))
}

// ListTasks 获取任务列表
// GET /api/v1/tasks
func (h *TasksHandler) ListTasks(c *gin.Context) {
	// 解析查询参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	status := c.Query("status")
	policyID := c.Query("policy_id")

	// 构建查询
	query := h.db.Model(&model.ScanTask{})

	// 过滤条件
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if policyID != "" {
		query = query.Where("policy_id = ?", policyID)
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询任务总数失败", zap.Error(err))
		InternalError(c, "查询任务列表失败")
		return
	}

	// 分页查询
	var tasks []model.ScanTask
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&tasks).Error; err != nil {
		h.logger.Error("查询任务列表失败", zap.Error(err))
		InternalError(c, "查询任务列表失败")
		return
	}

	// 为每个任务添加目标主机信息
	enrichedTasks := make([]*TaskResponse, len(tasks))
	for i := range tasks {
		enrichedTasks[i] = h.enrichTaskWithTargetHosts(&tasks[i])
	}

	SuccessPaginated(c, total, enrichedTasks)
}

// GetTask 获取任务详情
// GET /api/v1/tasks/:task_id
func (h *TasksHandler) GetTask(c *gin.Context) {
	taskID := c.Param("task_id")

	var task model.ScanTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询任务失败", zap.Error(err))
		InternalError(c, "查询任务失败")
		return
	}

	Success(c, h.enrichTaskWithTargetHosts(&task))
}

// TaskCheckAffectedHost 不通过的主机（受影响资源/不通过原因）
type TaskCheckAffectedHost struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Actual   string `json:"actual"` // 实际值（不通过的具体原因）
}

// TaskCheckItem 任务检查项（按规则聚合多台主机的结果）
type TaskCheckItem struct {
	RuleID        string                  `json:"rule_id"`
	Title         string                  `json:"title"`
	Category      string                  `json:"category"`
	Severity      string                  `json:"severity"`
	Description   string                  `json:"description"` // 说明（来自规则）
	Expected      string                  `json:"expected"`    // 检查依据（期望值）
	Remediation   string                  `json:"remediation"` // 修复建议
	Result        string                  `json:"result"`      // 合规结果：pass/fail/error/na
	HostTotal     int                     `json:"host_total"`  // 检查的主机数
	HostPassed    int                     `json:"host_passed"` // 通过的主机数
	HostFailed    int                     `json:"host_failed"` // 不通过的主机数
	HostError     int                     `json:"host_error"`  // 检查异常的主机数
	AffectedHosts []TaskCheckAffectedHost `json:"affected_hosts"`
}

// TaskChecksResponse 任务检查项响应（按规则聚合）
type TaskChecksResponse struct {
	Task     *TaskResponse   `json:"task"`
	Total    int             `json:"total"`     // 检查项总数（规则数）
	Passed   int             `json:"passed"`    // 通过的检查项数
	Failed   int             `json:"failed"`    // 不通过的检查项数
	ErrorCnt int             `json:"error_cnt"` // 检查异常的检查项数
	PassRate float64         `json:"pass_rate"` // 通过率 0-1
	Items    []TaskCheckItem `json:"items"`
}

// GetTaskChecks 获取任务的检查项明细（按规则聚合多台主机的合规结果）
// GET /api/v1/tasks/:task_id/checks?result=pass|fail
func (h *TasksHandler) GetTaskChecks(c *gin.Context) {
	taskID := c.Param("task_id")
	resultFilter := c.Query("result") // 可选：按合规结果过滤

	var task model.ScanTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询任务失败", zap.Error(err))
		InternalError(c, "查询任务失败")
		return
	}

	// 查询该任务的全部检测结果（每台主机每条规则一条），预加载规则以补全说明
	var results []model.ScanResult
	if err := h.db.Where("task_id = ?", taskID).
		Preload("Rule").
		Order("rule_id ASC").
		Find(&results).Error; err != nil {
		h.logger.Error("查询检测结果失败", zap.Error(err))
		InternalError(c, "查询检测结果失败")
		return
	}

	// 按 rule_id 聚合（order 保留首次出现顺序，即 SQL 排序）
	order := make([]string, 0)
	itemMap := make(map[string]*TaskCheckItem)
	for i := range results {
		r := &results[i]
		it, ok := itemMap[r.RuleID]
		if !ok {
			it = &TaskCheckItem{
				RuleID:        r.RuleID,
				Title:         r.Title,
				Category:      r.Category,
				Severity:      r.Severity,
				Description:   r.Rule.Description,
				Expected:      r.Expected,
				Remediation:   r.FixSuggestion,
				AffectedHosts: []TaskCheckAffectedHost{},
			}
			if it.Remediation == "" {
				it.Remediation = r.Rule.FixConfig.Suggestion
			}
			itemMap[r.RuleID] = it
			order = append(order, r.RuleID)
		}
		it.HostTotal++
		switch r.Status {
		case model.ResultStatusPass:
			it.HostPassed++
		case model.ResultStatusFail:
			it.HostFailed++
			it.AffectedHosts = append(it.AffectedHosts, TaskCheckAffectedHost{
				HostID:   r.HostID,
				Hostname: r.Hostname,
				Actual:   r.Actual,
			})
		case model.ResultStatusError:
			it.HostError++
		}
		// 用首个非空值补全聚合字段
		if it.Expected == "" && r.Expected != "" {
			it.Expected = r.Expected
		}
		if it.Description == "" && r.Rule.Description != "" {
			it.Description = r.Rule.Description
		}
	}

	resp := TaskChecksResponse{Task: h.enrichTaskWithTargetHosts(&task)}
	items := make([]TaskCheckItem, 0, len(order))
	for _, id := range order {
		it := itemMap[id]
		// 合规结果优先级：不通过 > 检查异常 > 通过 > 不适用
		switch {
		case it.HostFailed > 0:
			it.Result = string(model.ResultStatusFail)
		case it.HostError > 0:
			it.Result = string(model.ResultStatusError)
		case it.HostPassed > 0:
			it.Result = string(model.ResultStatusPass)
		default:
			it.Result = string(model.ResultStatusNA)
		}

		resp.Total++
		switch it.Result {
		case string(model.ResultStatusPass):
			resp.Passed++
		case string(model.ResultStatusFail):
			resp.Failed++
		case string(model.ResultStatusError):
			resp.ErrorCnt++
		}

		if resultFilter != "" && it.Result != resultFilter {
			continue
		}
		items = append(items, *it)
	}
	if resp.Total > 0 {
		resp.PassRate = float64(resp.Passed) / float64(resp.Total)
	}
	resp.Items = items

	Success(c, resp)
}

// RunTask 执行任务
// POST /api/v1/tasks/:task_id/run
func (h *TasksHandler) RunTask(c *gin.Context) {
	taskID := c.Param("task_id")

	var task model.ScanTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询任务失败", zap.Error(err))
		InternalError(c, "查询任务失败")
		return
	}

	// 只有 created / failed / partial 状态的任务可以（重新）执行
	// partial（部分完成）允许重跑以补齐剩余未返回结果的主机
	if task.Status != model.TaskStatusCreated &&
		task.Status != model.TaskStatusFailed &&
		task.Status != model.TaskStatusPartial {
		Conflict(c, "任务状态为 "+string(task.Status)+"，无法执行（仅允许 created/failed/partial 状态）")
		return
	}

	// 重置任务状态为 pending，等待调度器处理
	// 设置 executed_at 为执行请求时间（用于计算超时）
	// retry_count 归零：手动重跑视为全新一轮（dispatched/completed 计数同步归零，全量重扫）
	now := time.Now()
	localNow := model.LocalTime(now)
	if err := h.db.Model(&task).Updates(map[string]interface{}{
		"status":                model.TaskStatusPending,
		"executed_at":           &localNow,
		"retry_count":           0,
		"dispatched_host_count": 0,
		"completed_host_count":  0,
		"failed_reason":         "",
		"updated_at":            now,
	}).Error; err != nil {
		h.logger.Error("更新任务状态失败", zap.Error(err))
		InternalError(c, "更新任务状态失败")
		return
	}

	h.logger.Info("任务已标记为待执行", zap.String("task_id", taskID))

	// 重新查询更新后的任务
	h.db.Where("task_id = ?", taskID).First(&task)

	SuccessWithMessage(c, "任务已标记为待执行，等待调度器处理", h.enrichTaskWithTargetHosts(&task))
}

// CancelTask 取消任务
// POST /api/v1/tasks/:task_id/cancel
func (h *TasksHandler) CancelTask(c *gin.Context) {
	taskID := c.Param("task_id")

	var task model.ScanTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询任务失败", zap.Error(err))
		InternalError(c, "查询任务失败")
		return
	}

	// 检查任务状态，只有 created、pending 或 running 状态的任务可以取消
	if task.Status != model.TaskStatusCreated && task.Status != model.TaskStatusPending && task.Status != model.TaskStatusRunning {
		Conflict(c, "任务状态为 "+string(task.Status)+"，无法取消")
		return
	}

	// CAS：仅当状态仍为原值时更新，防止与调度器竞争
	now := time.Now()
	result := h.db.Model(&model.ScanTask{}).
		Where("task_id = ? AND status = ?", taskID, task.Status).
		Updates(map[string]interface{}{
			"status":       model.TaskStatusCancelled,
			"completed_at": now,
			"updated_at":   now,
		})
	if result.Error != nil {
		h.logger.Error("取消任务失败", zap.Error(result.Error))
		InternalError(c, "取消任务失败")
		return
	}
	if result.RowsAffected == 0 {
		Conflict(c, "任务状态已变更，请刷新后重试")
		return
	}

	// 向已下发的 Agent 发送取消信号（尽力而为，不阻塞响应）
	if task.Status == model.TaskStatusRunning && h.acDispatcher != nil {
		go h.sendCancelToAgents(taskID)
	}

	h.logger.Info("任务已取消", zap.String("task_id", taskID))

	// 重新查询更新后的任务
	h.db.Where("task_id = ?", taskID).First(&task)

	SuccessWithMessage(c, "任务已取消", h.enrichTaskWithTargetHosts(&task))
}

// sendCancelToAgents 向任务关联的所有 Agent 发送取消信号
func (h *TasksHandler) sendCancelToAgents(taskID string) {
	var hostStatuses []model.TaskHostStatus
	if err := h.db.Where("task_id = ? AND status = ?", taskID, model.TaskHostStatusDispatched).
		Find(&hostStatuses).Error; err != nil {
		h.logger.Error("查询任务主机状态失败", zap.String("task_id", taskID), zap.Error(err))
		return
	}

	cancelCmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			DataType:   9900, // 取消信号
			ObjectName: "baseline",
			Token:      taskID,
		}},
	}

	for _, hs := range hostStatuses {
		if err := h.acDispatcher.SendCommand(hs.HostID, cancelCmd); err != nil {
			h.logger.Debug("发送取消信号失败（Agent 可能已离线）",
				zap.String("task_id", taskID),
				zap.String("host_id", hs.HostID),
				zap.Error(err))
		}
	}
}

// DeleteTask 删除任务
// DELETE /api/v1/tasks/:task_id
func (h *TasksHandler) DeleteTask(c *gin.Context) {
	taskID := c.Param("task_id")

	var task model.ScanTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询任务失败", zap.Error(err))
		InternalError(c, "查询任务失败")
		return
	}

	// running 和 pending 状态的任务不能删除
	if task.Status == model.TaskStatusRunning || task.Status == model.TaskStatusPending {
		Conflict(c, "任务状态为 "+string(task.Status)+"，无法删除")
		return
	}

	// 事务中级联删除任务及关联数据
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("task_id = ?", task.TaskID).Delete(&model.TaskHostStatus{}).Error; err != nil {
			return err
		}
		if err := tx.Where("task_id = ?", task.TaskID).Delete(&model.ScanResult{}).Error; err != nil {
			return err
		}
		return tx.Delete(&task).Error
	}); err != nil {
		h.logger.Error("删除任务失败", zap.Error(err))
		InternalError(c, "删除任务失败")
		return
	}

	h.logger.Info("任务已删除（含关联数据）", zap.String("task_id", taskID))

	SuccessMessage(c, "任务已删除")
}

// GetTaskHostStatus 获取任务的主机执行状态
// GET /api/v1/tasks/:task_id/host-status
func (h *TasksHandler) GetTaskHostStatus(c *gin.Context) {
	taskID := c.Param("task_id")

	// 查询任务是否存在
	var task model.ScanTask
	if err := h.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "任务不存在")
			return
		}
		h.logger.Error("查询任务失败", zap.Error(err))
		InternalError(c, "查询任务失败")
		return
	}

	// 查询主机执行状态
	var hostStatuses []model.TaskHostStatus
	if err := h.db.Where("task_id = ?", taskID).
		Order("dispatched_at DESC").
		Find(&hostStatuses).Error; err != nil {
		h.logger.Error("查询主机执行状态失败", zap.Error(err))
		InternalError(c, "查询主机执行状态失败")
		return
	}

	Success(c, gin.H{
		"task_id": taskID,
		"hosts":   hostStatuses,
	})
}
