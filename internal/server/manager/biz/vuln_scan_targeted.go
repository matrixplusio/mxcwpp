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
	// MaxTargetedHostIDs 单次 OSV 关联的分批大小（原为对调用方的硬上限）。
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
		// 不再限制数量：核对与 OSV 关联都已在内部分批，
		// 内存占用与主机数无关。此前的 200 上限迫使调用方自己拆批，
		// 一个 228 台的机群要发两次请求，而两次之间的结果无法合并成一次任务。
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

	// global scope 先跑全库同步/增量扫描，再对全部主机做陈旧核对。
	//
	// 此前这里直接 return，reconcile 完全被跳过：全局扫描永远返回
	// scanned=0 / patched=0 且状态是成功——已修复的漏洞永远不会被核销，
	// 而调用方看到的是"扫过了，没什么要改的"。
	var hostIDs []string
	if task.Scope == model.ScanScopeGlobal {
		if task.SyncDB {
			execErr = m.scanner.ScanAll()
		} else {
			execErr = m.scanner.ScanIncremental()
		}
		if execErr != nil {
			return execErr
		}
		ids, err := m.allHostIDs()
		if err != nil {
			execErr = fmt.Errorf("取全部主机失败: %w", err)
			return execErr
		}
		hostIDs = ids
	} else if err := json.Unmarshal(task.TargetHostIDs, &hostIDs); err != nil {
		execErr = fmt.Errorf("解析 target_host_ids 失败: %w", err)
		return execErr
	}

	if len(hostIDs) == 0 {
		// 没有主机就没有可核对的东西。这不是错误，但要说清楚，
		// 否则又会退化成"成功且什么都没做"。
		m.logger.Info("扫描任务无目标主机，跳过核对",
			zap.Uint("task_id", task.ID), zap.String("scope", string(task.Scope)))
		return nil
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

	// OSV 关联同样按主机分批：一次性载入整个机群的 software 快照
	// 会让内存随机群规模线性增长，这正是此前设 200 台硬上限的原因。
	scanCtx, cancel := context.WithTimeout(ctx, TargetedScanTimeout)
	defer cancel()

	totalNewVulns := 0
	var osvErr error
	for start := 0; start < len(hostIDs); start += MaxTargetedHostIDs {
		end := min(start+MaxTargetedHostIDs, len(hostIDs))
		purls, purlInfoMap, err := m.loadPURLsForHosts(hostIDs[start:end])
		if err != nil {
			execErr = err
			return execErr
		}
		if len(purls) == 0 {
			continue
		}
		purls = advisory.FilterOSVPURLs(purls)
		coord := m.scanner.buildOSVCoordinator()
		// source 名必须是 "osv"：注册表里只有这一个 PURLSource。
		// 此前这里写的是 "osv-targeted"，一个从未注册过的名字，
		// 于是每一次 host-scoped 扫描都在这里报错。
		_, vulnCount, _, syncErr := coord.SyncByPURLs(
			scanCtx, "osv", purls, purlInfoMap, m.scanner.loadKnownVulnIDs())
		if syncErr != nil {
			osvErr = syncErr
			break
		}
		totalNewVulns += vulnCount
	}

	if osvErr != nil {
		// OSV 关联失败不推翻整个任务：reconcile 阶段的 patched/vanished
		// 已经落库并且是正确的，把任务整体标成 failed 会让运维以为
		// 那部分结果也不可信，从而重复执行一次代价很高的全量核对。
		// 与全库扫描路径的处理保持一致（那里同样只记录不中断）。
		m.logger.Error("OSV 关联失败，reconcile 结果仍然有效",
			zap.Uint("task_id", task.ID), zap.Error(osvErr))
		m.db.Model(&task).Update("error_msg", "OSV 关联失败: "+osvErr.Error())
	} else if totalNewVulns > 0 {
		m.db.Model(&task).Update("new_vulns", totalNewVulns)
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

// allHostIDs 取全部主机 ID，供 global scope 的陈旧核对使用。
//
// 只取在线与离线主机，不含已删除：对已删主机做核对没有意义，
// 而且会把它们的历史漏洞记录一并改状态。
func (m *ScanTaskManager) allHostIDs() ([]string, error) {
	var ids []string
	err := m.db.Model(&model.Host{}).Pluck("host_id", &ids).Error
	return ids, err
}
