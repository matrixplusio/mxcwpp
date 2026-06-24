package biz

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// 配置常量
const (
	// MaxTargetedHostIDs 单次 targeted 扫描的 host 上限，保护 server
	MaxTargetedHostIDs = 200
	// TargetedScanTimeout 单次 targeted 扫描总超时
	TargetedScanTimeout = 30 * time.Minute
)

// ScanTaskManager 漏洞扫描任务管理（生命周期 + 并发控制）
//
// 职责：
//   - 校验 + 解析扫描范围（scope=hosts/business_line/global）
//   - 并发交集校验（避免多 task 同时改同一 host_vulnerabilities）
//   - 异步 Execute：reconcile → OSV 关联 → resurface 检测
type ScanTaskManager struct {
	db         *gorm.DB
	logger     *zap.Logger
	scanner    *VulnScanner
	reconciler *VulnReconciler
}

// NewScanTaskManager 构造
func NewScanTaskManager(db *gorm.DB, logger *zap.Logger) *ScanTaskManager {
	return &ScanTaskManager{
		db:         db,
		logger:     logger,
		scanner:    NewVulnScanner(db, logger),
		reconciler: NewVulnReconciler(db, logger),
	}
}

// CreateTaskOpts 创建任务参数
type CreateTaskOpts struct {
	Scope          string
	HostIDs        []string
	BusinessLine   string
	SyncDB         bool
	ReconcileStale bool
	TriggeredBy    string
}

// Create 创建扫描任务（校验 + 解析 + 入库）
//
// 校验顺序：
//  1. scope 合法
//  2. scope=hosts: host_ids 非空 + 不超 MaxTargetedHostIDs
//  3. scope=business_line: 解析 host_ids
//  4. 检查与 running 任务 host_ids 交集（targeted 模式才校验）
func (m *ScanTaskManager) Create(opts CreateTaskOpts) (*model.VulnScanTask, error) {
	hostIDs, err := m.resolveHostIDs(opts)
	if err != nil {
		return nil, err
	}

	if opts.Scope != model.ScanScopeGlobal && len(hostIDs) > 0 {
		conflict, err := m.checkOverlapWithRunning(hostIDs)
		if err != nil {
			return nil, err
		}
		if conflict {
			return nil, fmt.Errorf("有运行中任务与本次主机集合存在交集，请稍后重试")
		}
	}

	targetJSON, _ := json.Marshal(hostIDs)
	task := &model.VulnScanTask{
		TaskID:         uuid.New().String(),
		Scope:          opts.Scope,
		TargetHostIDs:  datatypes.JSON(targetJSON),
		BusinessLine:   opts.BusinessLine,
		SyncDB:         opts.SyncDB,
		ReconcileStale: opts.ReconcileStale,
		Status:         model.ScanTaskStatusPending,
		ProgressTotal:  len(hostIDs),
		TriggeredBy:    opts.TriggeredBy,
	}
	if err := m.db.Create(task).Error; err != nil {
		return nil, fmt.Errorf("创建扫描任务失败: %w", err)
	}
	return task, nil
}

// resolveHostIDs 把 opts 解析为最终 host_ids 列表
func (m *ScanTaskManager) resolveHostIDs(opts CreateTaskOpts) ([]string, error) {
	switch opts.Scope {
	case model.ScanScopeGlobal:
		return nil, nil
	case model.ScanScopeHosts:
		if len(opts.HostIDs) == 0 {
			return nil, fmt.Errorf("scope=hosts 时 host_ids 不能为空")
		}
		if len(opts.HostIDs) > MaxTargetedHostIDs {
			return nil, fmt.Errorf("host_ids 数量 %d 超过上限 200", len(opts.HostIDs))
		}
		return opts.HostIDs, nil
	case model.ScanScopeBusinessLine:
		if opts.BusinessLine == "" {
			return nil, fmt.Errorf("scope=business_line 时 business_line 不能为空")
		}
		var hosts []model.Host
		if err := m.db.Where("business_line = ?", opts.BusinessLine).Find(&hosts).Error; err != nil {
			return nil, fmt.Errorf("查询业务线主机失败: %w", err)
		}
		if len(hosts) == 0 {
			return nil, fmt.Errorf("业务线 %s 下无主机", opts.BusinessLine)
		}
		if len(hosts) > MaxTargetedHostIDs {
			return nil, fmt.Errorf("业务线 %s 主机数 %d 超过上限 200", opts.BusinessLine, len(hosts))
		}
		ids := make([]string, len(hosts))
		for i, h := range hosts {
			ids[i] = h.HostID
		}
		return ids, nil
	default:
		return nil, fmt.Errorf("不支持的 scope: %s", opts.Scope)
	}
}

// checkOverlapWithRunning 校验 host_ids 与正在跑的 targeted 任务是否交集
func (m *ScanTaskManager) checkOverlapWithRunning(hostIDs []string) (bool, error) {
	var running []model.VulnScanTask
	err := m.db.Where("status = ? AND scope IN ?",
		model.ScanTaskStatusRunning,
		[]string{model.ScanScopeHosts, model.ScanScopeBusinessLine}).
		Find(&running).Error
	if err != nil {
		return false, err
	}

	newSet := make(map[string]struct{}, len(hostIDs))
	for _, h := range hostIDs {
		newSet[h] = struct{}{}
	}

	for _, task := range running {
		var existing []string
		if err := json.Unmarshal(task.TargetHostIDs, &existing); err != nil {
			continue
		}
		for _, h := range existing {
			if _, ok := newSet[h]; ok {
				return true, nil
			}
		}
	}
	return false, nil
}

// Execute 异步执行扫描（由 API 层在 goroutine 中调用）
//
// 流程：
//  1. running 标记
//  2. (optional) reconcile 陈旧
//  3. (optional) OSV 同步
//  4. PURL → CVE 关联
//  5. resurface 检测
//  6. success/failed 标记
func (m *ScanTaskManager) Execute(ctx context.Context, taskID string) error {
	var task model.VulnScanTask
	if err := m.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		return fmt.Errorf("任务不存在: %w", err)
	}

	startedAt := model.LocalTime(time.Now())
	m.db.Model(&task).Updates(map[string]any{
		"status":     model.ScanTaskStatusRunning,
		"started_at": &startedAt,
	})

	var execErr error
	defer func() {
		finalStatus := model.ScanTaskStatusSuccess
		errMsg := ""
		if execErr != nil {
			finalStatus = model.ScanTaskStatusFailed
			errMsg = execErr.Error()
		}
		finished := model.LocalTime(time.Now())
		m.db.Model(&task).Updates(map[string]any{
			"status":      finalStatus,
			"finished_at": &finished,
			"error_msg":   errMsg,
		})
	}()

	// global scope 直接转回旧路径
	if task.Scope == model.ScanScopeGlobal {
		if task.SyncDB {
			execErr = m.scanner.ScanAll()
		} else {
			execErr = m.scanner.ScanIncremental()
		}
		return execErr
	}

	var hostIDs []string
	if err := json.Unmarshal(task.TargetHostIDs, &hostIDs); err != nil {
		execErr = fmt.Errorf("解析 target_host_ids 失败: %w", err)
		return execErr
	}

	// Targeted: reconcile → OSV → resurface
	if task.ReconcileStale {
		result, err := m.reconciler.ReconcileHosts(hostIDs)
		if err != nil {
			execErr = fmt.Errorf("reconcile 失败: %w", err)
			return execErr
		}
		m.db.Model(&task).Updates(map[string]any{
			"patched_count":  result.Patched,
			"vanished_count": result.Vanished,
		})
	}

	purls, purlInfoMap, err := m.loadPURLsForHosts(hostIDs)
	if err != nil {
		execErr = err
		return execErr
	}
	if len(purls) > 0 {
		purls = advisory.FilterOSVPURLs(purls)
		coord := m.scanner.buildOSVCoordinator()
		scanCtx, cancel := context.WithTimeout(ctx, TargetedScanTimeout)
		defer cancel()
		_, vulnCount, _, syncErr := coord.SyncByPURLs(
			scanCtx, "osv-targeted", purls, purlInfoMap, m.scanner.loadKnownVulnIDs())
		if syncErr != nil {
			execErr = fmt.Errorf("OSV 关联失败: %w", syncErr)
			return execErr
		}
		m.db.Model(&task).Update("new_vulns", vulnCount)
	}

	if task.ReconcileStale {
		count := m.reconciler.DetectResurfaced(hostIDs)
		m.db.Model(&task).Update("resurfaced_count", count)
	}

	m.db.Model(&task).Update("progress_scanned", task.ProgressTotal)
	return nil
}

// loadPURLsForHosts 取指定 host 的 PURL 用于 OSV 关联
func (m *ScanTaskManager) loadPURLsForHosts(hostIDs []string) ([]string, map[string]advisory.PURLPkgInfo, error) {
	var packages []purlInfo
	err := m.db.Table("software AS s").
		Select("s.purl AS purl, s.name AS name, s.version AS version, s.host_id AS host_id, COALESCE(NULLIF(s.scope, ''), 'system') AS scope, COALESCE(h.hostname, '') AS hostname, COALESCE(JSON_UNQUOTE(JSON_EXTRACT(h.ipv4, '$[0]')), '') AS ip").
		Joins("LEFT JOIN hosts h ON h.host_id = s.host_id").
		Where("s.host_id IN ? AND s.purl != '' AND s.purl IS NOT NULL", hostIDs).
		Scan(&packages).Error
	if err != nil {
		return nil, nil, fmt.Errorf("查询 software 失败: %w", err)
	}
	purls, infoMap := buildPURLPkgInfo(packages)
	return purls, infoMap, nil
}
