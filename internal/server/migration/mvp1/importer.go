package mvp1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// 迁移表顺序（按依赖关系）
var migrationTables = []string{
	"users",
	"business_lines",
	"hosts",
	"policies",
	"rules",
	"scan_tasks",
	"scan_results",
	"notifications",
}

// 表标签（中文）
var tableLabels = map[string]string{
	"users":          "用户",
	"business_lines": "业务线",
	"hosts":          "主机",
	"policies":       "策略",
	"rules":          "规则",
	"scan_tasks":     "扫描任务",
	"scan_results":   "扫描结果",
	"notifications":  "通知配置",
}

// MVP1 API 路径
var tableAPIPaths = map[string]string{
	"users":          "/api/v1/users",
	"business_lines": "/api/v1/business-lines",
	"hosts":          "/api/v1/hosts",
	"policies":       "/api/v1/policies",
	"scan_tasks":     "/api/v1/tasks",
	"scan_results":   "/api/v1/results",
	"notifications":  "/api/v1/notifications",
}

// Importer MVP1 数据迁移器
type Importer struct {
	client *Client
	db     *gorm.DB
	logger *zap.Logger
	job    *model.MigrationJob

	// oldID → newID 映射（仅用于 uint 主键的表）
	userIDMap         map[uint]uint
	businessLineIDMap map[uint]uint
	notificationIDMap map[uint]uint
}

// NewImporter 创建迁移器
func NewImporter(client *Client, db *gorm.DB, logger *zap.Logger, job *model.MigrationJob) *Importer {
	return &Importer{
		client:            client,
		db:                db,
		logger:            logger,
		job:               job,
		userIDMap:         make(map[uint]uint),
		businessLineIDMap: make(map[uint]uint),
		notificationIDMap: make(map[uint]uint),
	}
}

// Run 执行迁移（在后台 goroutine 中调用）
func (imp *Importer) Run(ctx context.Context) {
	now := model.Now()
	imp.job.StartedAt = &now
	imp.job.Status = "running"
	imp.db.Save(imp.job)

	// 过滤 scope
	scope := imp.filterScope()
	if len(scope) == 0 {
		imp.finishWithError("未选择任何迁移范围")
		return
	}

	reports := make([]TableReport, 0, len(scope))
	totalCreated, totalSkipped, totalFailed := 0, 0, 0

	for i, table := range scope {
		select {
		case <-ctx.Done():
			imp.job.Status = "cancelled"
			imp.job.Error = "用户取消"
			fin := model.Now()
			imp.job.FinishedAt = &fin
			imp.saveReports(reports)
			imp.db.Save(imp.job)
			return
		default:
		}

		imp.job.CurrentTable = tableLabels[table]
		imp.job.Progress = i * 100 / len(scope)
		imp.db.Save(imp.job)

		imp.logger.Info("开始迁移表", zap.String("table", table))

		report, err := imp.migrateTable(ctx, table)
		if err != nil {
			imp.logger.Error("迁移表失败", zap.String("table", table), zap.Error(err))
			report = &TableReport{
				Table:      tableLabels[table],
				Failed:     1,
				FailErrors: []string{err.Error()},
			}
		}

		reports = append(reports, *report)
		totalCreated += report.Created
		totalSkipped += report.Skipped
		totalFailed += report.Failed

		imp.job.CreatedCount = totalCreated
		imp.job.SkippedCount = totalSkipped
		imp.job.FailedCount = totalFailed
		imp.db.Save(imp.job)

		imp.logger.Info("表迁移完成",
			zap.String("table", table),
			zap.Int("created", report.Created),
			zap.Int("skipped", report.Skipped),
			zap.Int("failed", report.Failed))
	}

	imp.job.Status = "completed"
	imp.job.Progress = 100
	imp.job.CurrentTable = ""
	fin := model.Now()
	imp.job.FinishedAt = &fin
	imp.saveReports(reports)
	imp.db.Save(imp.job)

	imp.logger.Info("MVP1 数据迁移完成",
		zap.Int("created", totalCreated),
		zap.Int("skipped", totalSkipped),
		zap.Int("failed", totalFailed))
}

// filterScope 过滤有效的 scope 并按依赖顺序排列
func (imp *Importer) filterScope() []string {
	scopeSet := make(map[string]bool)
	for _, s := range imp.job.Scope {
		scopeSet[s] = true
	}

	var result []string
	for _, t := range migrationTables {
		if scopeSet[t] {
			result = append(result, t)
		}
	}
	return result
}

// migrateTable 迁移单个表
func (imp *Importer) migrateTable(ctx context.Context, table string) (*TableReport, error) {
	switch table {
	case "users":
		return imp.migrateUsers(ctx)
	case "business_lines":
		return imp.migrateBusinessLines(ctx)
	case "hosts":
		return imp.migrateHosts(ctx)
	case "policies":
		return imp.migratePolicies(ctx)
	case "rules":
		return imp.migrateRules(ctx)
	case "scan_tasks":
		return imp.migrateScanTasks(ctx)
	case "scan_results":
		return imp.migrateScanResults(ctx)
	case "notifications":
		return imp.migrateNotifications(ctx)
	default:
		return nil, fmt.Errorf("未知表: %s", table)
	}
}

// --- 各表迁移实现 ---

func (imp *Importer) migrateUsers(ctx context.Context) (*TableReport, error) {
	rawItems, err := imp.client.ListAll(tableAPIPaths["users"], 100)
	if err != nil {
		return nil, fmt.Errorf("拉取用户数据失败: %w", err)
	}

	report := &TableReport{Table: "用户", Total: len(rawItems)}

	for _, raw := range rawItems {
		if ctx.Err() != nil {
			return report, nil
		}
		var src mvp1User
		if err := json.Unmarshal(raw, &src); err != nil {
			report.addFail("解析用户 JSON 失败: " + err.Error())
			continue
		}

		// 冲突判定：username
		var existing model.User
		if err := imp.db.Where("username = ?", src.Username).First(&existing).Error; err == nil {
			imp.userIDMap[src.ID] = existing.ID
			report.addSkip(fmt.Sprintf("用户 %s 已存在", src.Username))
			continue
		}

		newUser := model.User{
			Username:  src.Username,
			Password:  "$invalid$migrated$",
			Email:     src.Email,
			Role:      model.UserRole(src.Role),
			Status:    model.UserStatus(src.Status),
			CreatedAt: parseTime(src.CreatedAt),
			UpdatedAt: parseTime(src.UpdatedAt),
		}
		if err := imp.db.Create(&newUser).Error; err != nil {
			report.addFail(fmt.Sprintf("创建用户 %s 失败: %s", src.Username, err.Error()))
			continue
		}
		imp.userIDMap[src.ID] = newUser.ID
		report.Created++
	}
	return report, nil
}

func (imp *Importer) migrateBusinessLines(ctx context.Context) (*TableReport, error) {
	rawItems, err := imp.client.ListAll(tableAPIPaths["business_lines"], 100)
	if err != nil {
		return nil, fmt.Errorf("拉取业务线数据失败: %w", err)
	}

	report := &TableReport{Table: "业务线", Total: len(rawItems)}

	for _, raw := range rawItems {
		if ctx.Err() != nil {
			return report, nil
		}
		var src mvp1BusinessLine
		if err := json.Unmarshal(raw, &src); err != nil {
			report.addFail("解析业务线 JSON 失败: " + err.Error())
			continue
		}

		var existing model.BusinessLine
		if err := imp.db.Where("name = ?", src.Name).First(&existing).Error; err == nil {
			imp.businessLineIDMap[src.ID] = existing.ID
			report.addSkip(fmt.Sprintf("业务线 %s 已存在", src.Name))
			continue
		}

		newBL := model.BusinessLine{
			Name:        src.Name,
			Code:        src.Code,
			Description: src.Description,
			Owner:       src.Owner,
			Contact:     src.Contact,
			Enabled:     src.Enabled,
			CreatedAt:   parseTime(src.CreatedAt),
			UpdatedAt:   parseTime(src.UpdatedAt),
		}
		if err := imp.db.Create(&newBL).Error; err != nil {
			report.addFail(fmt.Sprintf("创建业务线 %s 失败: %s", src.Name, err.Error()))
			continue
		}
		imp.businessLineIDMap[src.ID] = newBL.ID
		report.Created++
	}
	return report, nil
}

func (imp *Importer) migrateHosts(ctx context.Context) (*TableReport, error) {
	rawItems, err := imp.client.ListAll(tableAPIPaths["hosts"], 100)
	if err != nil {
		return nil, fmt.Errorf("拉取主机数据失败: %w", err)
	}

	report := &TableReport{Table: "主机", Total: len(rawItems)}

	for _, raw := range rawItems {
		if ctx.Err() != nil {
			return report, nil
		}
		var src mvp1Host
		if err := json.Unmarshal(raw, &src); err != nil {
			report.addFail("解析主机 JSON 失败: " + err.Error())
			continue
		}

		// 冲突判定：host_id (agent_id)
		var existing model.Host
		if err := imp.db.Where("host_id = ?", src.HostID).First(&existing).Error; err == nil {
			report.addSkip(fmt.Sprintf("主机 %s (%s) 已存在", src.Hostname, src.HostID[:8]))
			continue
		}

		newHost := model.Host{
			HostID:        src.HostID,
			Hostname:      src.Hostname,
			OSFamily:      src.OSFamily,
			OSVersion:     src.OSVersion,
			KernelVersion: src.KernelVersion,
			Arch:          src.Arch,
			IPv4:          model.StringArray(src.IPv4),
			IPv6:          model.StringArray(src.IPv6),
			PublicIPv4:    model.StringArray(src.PublicIPv4),
			PublicIPv6:    model.StringArray(src.PublicIPv6),
			Status:        model.HostStatusOffline, // 迁移后默认离线，等 Agent 重连
			BusinessLine:  src.BusinessLine,
			AgentVersion:  src.AgentVersion,
			Tags:          model.StringArray(src.Tags),
			CPUInfo:       src.CPUInfo,
			MemorySize:    src.MemorySize,
			DiskInfo:      src.DiskInfo,
			RuntimeType:   model.RuntimeTypeVM,
			CreatedAt:     parseTime(src.CreatedAt),
			UpdatedAt:     parseTime(src.UpdatedAt),
		}
		if err := imp.db.Create(&newHost).Error; err != nil {
			report.addFail(fmt.Sprintf("创建主机 %s 失败: %s", src.Hostname, err.Error()))
			continue
		}
		report.Created++
	}
	return report, nil
}

func (imp *Importer) migratePolicies(ctx context.Context) (*TableReport, error) {
	rawItems, err := imp.client.ListAll(tableAPIPaths["policies"], 100)
	if err != nil {
		return nil, fmt.Errorf("拉取策略数据失败: %w", err)
	}

	report := &TableReport{Table: "策略", Total: len(rawItems)}

	for _, raw := range rawItems {
		if ctx.Err() != nil {
			return report, nil
		}
		var src mvp1Policy
		if err := json.Unmarshal(raw, &src); err != nil {
			report.addFail("解析策略 JSON 失败: " + err.Error())
			continue
		}

		// 冲突判定：policy_id
		var existing model.Policy
		if err := imp.db.Where("id = ?", src.ID).First(&existing).Error; err == nil {
			report.addSkip(fmt.Sprintf("策略 %s 已存在", src.Name))
			continue
		}

		newPolicy := model.Policy{
			ID:           src.ID,
			Name:         src.Name,
			Version:      src.Version,
			Description:  src.Description,
			OSFamily:     model.StringArray(src.OSFamily),
			OSVersion:    src.OSVersion,
			Enabled:      src.Enabled,
			GroupID:      src.GroupID,
			RuntimeTypes: model.StringArray{"vm"},
			CreatedAt:    parseTime(src.CreatedAt),
			UpdatedAt:    parseTime(src.UpdatedAt),
		}
		if err := imp.db.Create(&newPolicy).Error; err != nil {
			report.addFail(fmt.Sprintf("创建策略 %s 失败: %s", src.Name, err.Error()))
			continue
		}
		report.Created++
	}
	return report, nil
}

func (imp *Importer) migrateRules(ctx context.Context) (*TableReport, error) {
	// 需要先获取所有策略 ID，然后逐策略拉取规则
	rawPolicies, err := imp.client.ListAll(tableAPIPaths["policies"], 100)
	if err != nil {
		return nil, fmt.Errorf("拉取策略列表失败: %w", err)
	}

	report := &TableReport{Table: "规则"}

	for _, rawPolicy := range rawPolicies {
		if ctx.Err() != nil {
			return report, nil
		}
		var p mvp1Policy
		if err := json.Unmarshal(rawPolicy, &p); err != nil {
			continue
		}

		path := fmt.Sprintf("/api/v1/policies/%s/rules", p.ID)
		rawRules, err := imp.client.ListAll(path, 200)
		if err != nil {
			report.addFail(fmt.Sprintf("拉取策略 %s 的规则失败: %s", p.Name, err.Error()))
			continue
		}

		for _, rawRule := range rawRules {
			if ctx.Err() != nil {
				return report, nil
			}
			report.Total++

			var src mvp1Rule
			if err := json.Unmarshal(rawRule, &src); err != nil {
				report.addFail("解析规则 JSON 失败: " + err.Error())
				continue
			}

			// 冲突判定：rule_id
			var existing model.Rule
			if err := imp.db.Where("rule_id = ?", src.RuleID).First(&existing).Error; err == nil {
				report.addSkip(fmt.Sprintf("规则 %s 已存在", src.RuleID))
				continue
			}

			checkCfg := marshalRawJSON(src.CheckConfig)
			fixCfg := marshalRawJSON(src.FixConfig)

			var cc model.CheckConfig
			_ = json.Unmarshal([]byte(checkCfg), &cc)
			var fc model.FixConfig
			_ = json.Unmarshal([]byte(fixCfg), &fc)

			newRule := model.Rule{
				RuleID:      src.RuleID,
				PolicyID:    src.PolicyID,
				Category:    src.Category,
				Title:       src.Title,
				Description: src.Description,
				Severity:    src.Severity,
				Enabled:     src.Enabled,
				CheckConfig: cc,
				FixConfig:   fc,
				CreatedAt:   parseTime(src.CreatedAt),
				UpdatedAt:   parseTime(src.UpdatedAt),
			}
			if err := imp.db.Create(&newRule).Error; err != nil {
				report.addFail(fmt.Sprintf("创建规则 %s 失败: %s", src.RuleID, err.Error()))
				continue
			}
			report.Created++
		}
	}
	return report, nil
}

func (imp *Importer) migrateScanTasks(ctx context.Context) (*TableReport, error) {
	rawItems, err := imp.client.ListAll(tableAPIPaths["scan_tasks"], 100)
	if err != nil {
		return nil, fmt.Errorf("拉取扫描任务失败: %w", err)
	}

	report := &TableReport{Table: "扫描任务", Total: len(rawItems)}

	for _, raw := range rawItems {
		if ctx.Err() != nil {
			return report, nil
		}
		var src mvp1ScanTask
		if err := json.Unmarshal(raw, &src); err != nil {
			report.addFail("解析任务 JSON 失败: " + err.Error())
			continue
		}

		// scan_tasks 用 task_id 判重
		var existing model.ScanTask
		if err := imp.db.Where("task_id = ?", src.TaskID).First(&existing).Error; err == nil {
			report.addSkip(fmt.Sprintf("任务 %s 已存在", src.TaskID[:8]))
			continue
		}

		targetCfgJSON := marshalRawJSON(src.TargetConfig)
		var tc model.TargetConfig
		_ = json.Unmarshal([]byte(targetCfgJSON), &tc)

		newTask := model.ScanTask{
			TaskID:         src.TaskID,
			Name:           src.Name,
			Type:           model.TaskType(src.Type),
			TargetType:     model.TargetType(src.TargetType),
			TargetConfig:   tc,
			PolicyID:       src.PolicyID,
			PolicyIDs:      model.StringArray(src.PolicyIDs),
			RuleIDs:        model.StringArray(src.RuleIDs),
			Status:         model.TaskStatus(src.Status),
			TimeoutMinutes: src.TimeoutMinutes,
			CreatedAt:      parseTime(src.CreatedAt),
			UpdatedAt:      parseTime(src.UpdatedAt),
			ExecutedAt:     parseTimePtr(src.ExecutedAt),
			CompletedAt:    parseTimePtr(src.CompletedAt),
		}
		if err := imp.db.Create(&newTask).Error; err != nil {
			report.addFail(fmt.Sprintf("创建任务 %s 失败: %s", src.Name, err.Error()))
			continue
		}
		report.Created++
	}
	return report, nil
}

func (imp *Importer) migrateScanResults(ctx context.Context) (*TableReport, error) {
	rawItems, err := imp.client.ListAll(tableAPIPaths["scan_results"], 200)
	if err != nil {
		return nil, fmt.Errorf("拉取扫描结果失败: %w", err)
	}

	report := &TableReport{Table: "扫描结果", Total: len(rawItems)}

	for _, raw := range rawItems {
		if ctx.Err() != nil {
			return report, nil
		}
		var src mvp1ScanResult
		if err := json.Unmarshal(raw, &src); err != nil {
			report.addFail("解析结果 JSON 失败: " + err.Error())
			continue
		}

		// 复合主键 (task_id, host_id, rule_id) 判重
		var existing model.ScanResult
		if err := imp.db.Where("task_id = ? AND host_id = ? AND rule_id = ?", src.TaskID, src.HostID, src.RuleID).First(&existing).Error; err == nil {
			report.addSkip(fmt.Sprintf("结果 %s/%s 已存在", src.HostID[:8], src.RuleID))
			continue
		}

		newResult := model.ScanResult{
			TaskID:        src.TaskID,
			HostID:        src.HostID,
			RuleID:        src.RuleID,
			Hostname:      src.Hostname,
			PolicyID:      src.PolicyID,
			PolicyName:    src.PolicyName,
			Status:        model.ResultStatus(src.Status),
			Severity:      src.Severity,
			Category:      src.Category,
			Title:         src.Title,
			Actual:        src.Actual,
			Expected:      src.Expected,
			FixSuggestion: src.FixSuggestion,
			CheckedAt:     parseTime(src.CheckedAt),
			CreatedAt:     parseTime(src.CreatedAt),
		}
		if err := imp.db.Create(&newResult).Error; err != nil {
			report.addFail(fmt.Sprintf("创建结果 %s/%s 失败: %s", src.HostID[:8], src.RuleID, err.Error()))
			continue
		}
		report.Created++
	}
	return report, nil
}

func (imp *Importer) migrateNotifications(ctx context.Context) (*TableReport, error) {
	rawItems, err := imp.client.ListAll(tableAPIPaths["notifications"], 100)
	if err != nil {
		return nil, fmt.Errorf("拉取通知配置失败: %w", err)
	}

	report := &TableReport{Table: "通知配置", Total: len(rawItems)}

	for _, raw := range rawItems {
		if ctx.Err() != nil {
			return report, nil
		}
		var src mvp1Notification
		if err := json.Unmarshal(raw, &src); err != nil {
			report.addFail("解析通知 JSON 失败: " + err.Error())
			continue
		}

		// 冲突判定：name
		var existing model.Notification
		if err := imp.db.Where("name = ?", src.Name).First(&existing).Error; err == nil {
			imp.notificationIDMap[src.ID] = existing.ID
			report.addSkip(fmt.Sprintf("通知 %s 已存在", src.Name))
			continue
		}

		cfgJSON := marshalRawJSON(src.Config)
		var nc model.NotificationConfig
		_ = json.Unmarshal([]byte(cfgJSON), &nc)

		// MVP1 可能没有 notify_category 字段，默认设为 baseline_alert
		notifyCategory := model.NotifyCategoryBaselineAlert

		newNotif := model.Notification{
			Name:           src.Name,
			Description:    src.Description,
			NotifyCategory: notifyCategory,
			Enabled:        src.Enabled,
			Type:           model.NotificationType(src.Type),
			Severities:     model.StringArray(src.Severities),
			Scope:          model.NotificationScope(src.Scope),
			ScopeValue:     src.ScopeValue,
			FrontendURL:    src.FrontendURL,
			Config:         nc,
			CreatedAt:      parseTime(src.CreatedAt),
			UpdatedAt:      parseTime(src.UpdatedAt),
		}
		if err := imp.db.Create(&newNotif).Error; err != nil {
			report.addFail(fmt.Sprintf("创建通知 %s 失败: %s", src.Name, err.Error()))
			continue
		}
		imp.notificationIDMap[src.ID] = newNotif.ID
		report.Created++
	}
	return report, nil
}

// --- 辅助方法 ---

func (imp *Importer) finishWithError(msg string) {
	imp.job.Status = "failed"
	imp.job.Error = msg
	fin := model.Now()
	imp.job.FinishedAt = &fin
	imp.db.Save(imp.job)
}

func (imp *Importer) saveReports(reports []TableReport) {
	total := 0
	for _, r := range reports {
		total += r.Total
	}
	imp.job.TotalRecords = total

	data, _ := json.Marshal(reports)
	imp.job.Report = string(data)
}

// parseTime 解析 MVP1 时间字符串
func parseTime(s string) model.LocalTime {
	if s == "" {
		return model.LocalTime{}
	}
	formats := []string{
		model.TimeFormat,
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return model.LocalTime(t)
		}
	}
	return model.LocalTime{}
}

// parseTimePtr 解析可空时间
func parseTimePtr(s *string) *model.LocalTime {
	if s == nil || *s == "" {
		return nil
	}
	t := parseTime(*s)
	return &t
}

// marshalRawJSON 将 interface{} 编码为 JSON 字符串
func marshalRawJSON(v interface{}) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// addSkip 向报告追加跳过原因（最多 50 条）
func (r *TableReport) addSkip(reason string) {
	r.Skipped++
	if len(r.SkipReasons) < 50 {
		r.SkipReasons = append(r.SkipReasons, reason)
	}
}

// addFail 向报告追加失败原因（最多 50 条）
func (r *TableReport) addFail(errMsg string) {
	r.Failed++
	if len(r.FailErrors) < 50 {
		r.FailErrors = append(r.FailErrors, errMsg)
	}
}
