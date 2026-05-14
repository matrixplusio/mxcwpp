package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
)

// Engine FIM 检查引擎
type Engine struct {
	logger   *zap.Logger
	scanner  *Scanner
	baseline *BaselineStore
}

// NewEngine 创建引擎实例
func NewEngine(logger *zap.Logger) *Engine {
	return &Engine{
		logger:   logger,
		scanner:  NewScanner(logger),
		baseline: NewBaselineStore(logger),
	}
}

// Execute 执行 FIM 检查流程
func (e *Engine) Execute(ctx context.Context, taskData json.RawMessage) (*ExecuteResult, error) {
	// 1. 解析策略
	policy, err := e.parsePolicyFromTask(taskData)
	if err != nil {
		return nil, fmt.Errorf("解析策略失败: %w", err)
	}

	// 2. 扫描文件
	e.logger.Info("开始文件扫描",
		zap.String("policy_id", policy.PolicyID),
		zap.Int("watch_paths", len(policy.WatchPaths)))
	scanResult, err := e.scanner.Scan(ctx, policy)
	if err != nil {
		return nil, fmt.Errorf("文件扫描失败: %w", err)
	}
	e.logger.Info("文件扫描完成",
		zap.Int("file_count", len(scanResult.Entries)),
		zap.Int("errors", len(scanResult.Errors)))

	// 3. 加载基线
	bl, err := e.baseline.Load(policy.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("加载基线失败: %w", err)
	}

	// 4. 无基线（首次扫描）→ 保存初始基线，上报快照供服务端审批
	if bl == nil {
		e.logger.Info("首次扫描，生成初始基线",
			zap.String("policy_id", policy.PolicyID),
			zap.Int("entry_count", len(scanResult.Entries)))
		newBL := e.baseline.NewBaseline(policy.PolicyID, scanResult.Entries)
		if err := e.baseline.Save(newBL); err != nil {
			return nil, fmt.Errorf("保存初始基线失败: %w", err)
		}
		return &ExecuteResult{
			PolicyID: policy.PolicyID,
			Summary: FIMSummary{
				TotalEntries: len(scanResult.Entries),
			},
			IsInitialBaseline: true,
			Snapshot:          scanResult.Entries,
		}, nil
	}

	// 5. 有基线 → 对比生成事件
	events := compare(bl, scanResult)

	// 6. 分类每个事件
	for i := range events {
		Classify(&events[i])
	}

	summary := FIMSummary{TotalEntries: len(scanResult.Entries)}
	for _, ev := range events {
		switch ev.ChangeType {
		case "added":
			summary.AddedEntries++
		case "removed":
			summary.RemovedEntries++
		case "changed":
			summary.ChangedEntries++
		}
	}

	return &ExecuteResult{
		PolicyID: policy.PolicyID,
		Summary:  summary,
		Events:   events,
	}, nil
}

// SaveBaseline 保存服务端下发的审批基线
func (e *Engine) SaveBaseline(taskData json.RawMessage) error {
	var bl Baseline
	if err := json.Unmarshal(taskData, &bl); err != nil {
		return fmt.Errorf("解析基线数据失败: %w", err)
	}
	return e.baseline.Save(&bl)
}

// parsePolicyFromTask 从任务 JSON 提取策略配置
func (e *Engine) parsePolicyFromTask(taskData json.RawMessage) (*FIMPolicy, error) {
	var policy FIMPolicy
	if err := json.Unmarshal(taskData, &policy); err != nil {
		return nil, fmt.Errorf("解析策略 JSON 失败: %w", err)
	}
	if len(policy.WatchPaths) == 0 {
		return nil, fmt.Errorf("策略未配置监控路径")
	}
	return &policy, nil
}

// compare 对比基线与当前扫描结果，生成变更事件
func compare(bl *Baseline, current *ScanResult) []FIMEvent {
	var events []FIMEvent
	counter := 0

	// 已删除文件（基线中有，当前没有）
	for path := range bl.Entries {
		if _, exists := current.Entries[path]; !exists {
			counter++
			events = append(events, FIMEvent{
				EventID:    fmt.Sprintf("evt-%06d", counter),
				FilePath:   path,
				ChangeType: "removed",
			})
		}
	}

	// 新增和变更文件
	for path, curEntry := range current.Entries {
		blEntry, exists := bl.Entries[path]
		if !exists {
			counter++
			events = append(events, FIMEvent{
				EventID:    fmt.Sprintf("evt-%06d", counter),
				FilePath:   path,
				ChangeType: "added",
			})
			continue
		}

		if detail := compareEntries(blEntry, curEntry); detail != nil {
			counter++
			events = append(events, FIMEvent{
				EventID:      fmt.Sprintf("evt-%06d", counter),
				FilePath:     path,
				ChangeType:   "changed",
				ChangeDetail: *detail,
			})
		}
	}

	return events
}

// compareEntries 比较两个文件条目，返回变更详情（无变更返回 nil）
func compareEntries(old, cur FileEntry) *ChangeDetail {
	detail := &ChangeDetail{}
	changed := false

	if old.SHA256 != "" && cur.SHA256 != "" && old.SHA256 != cur.SHA256 {
		detail.HashChanged = true
		detail.HashBefore = old.SHA256
		detail.HashAfter = cur.SHA256
		changed = true
	}

	if old.Size != cur.Size {
		detail.SizeBefore = fmt.Sprintf("%d", old.Size)
		detail.SizeAfter = fmt.Sprintf("%d", cur.Size)
		changed = true
	}

	if old.Mode != "" && cur.Mode != "" && old.Mode != cur.Mode {
		detail.PermissionChanged = true
		detail.ModeBefore = old.Mode
		detail.ModeAfter = cur.Mode
		changed = true
	}

	if old.UID != cur.UID || old.GID != cur.GID {
		detail.OwnerChanged = true
		changed = true
	}

	if !changed {
		return nil
	}
	return detail
}
