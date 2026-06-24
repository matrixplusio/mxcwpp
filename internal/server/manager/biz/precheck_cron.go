// Package biz — Pre-check 周期巡检 cron。
//
// 每 6h 扫描 host_vulnerabilities 中需要 pre-check 的条目：
//   - status='unpatched'
//   - 且 precheck_status IN ('unchecked', 'failed')  OR  precheck_checked_at < now-24h
//
// 按 host_id 分组（同 host 一批，复用 agent 端 dnf metadata cache），
// 每条之间 sleep 200ms 防 agent 抗压；每 host 之间 sleep 2s。
package biz

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// PreCheckCron 周期 pre-check 巡检
type PreCheckCron struct {
	db         *gorm.DB
	logger     *zap.Logger
	dispatcher PreCheckDispatcher
	interval   time.Duration
	cacheTTL   time.Duration
	maxBatch   int // 单 host 单次最多 dispatch 多少
}

// PreCheckDispatcher 与 sd.ACDispatcher 抽象的最小接口（便于测试 mock）
type PreCheckDispatcher interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}

// NewPreCheckCron 默认 6h 轮询、24h 缓存、单 host 单次 ≤ 200 条
func NewPreCheckCron(db *gorm.DB, logger *zap.Logger, dispatcher PreCheckDispatcher) *PreCheckCron {
	return &PreCheckCron{
		db:         db,
		logger:     logger,
		dispatcher: dispatcher,
		interval:   6 * time.Hour,
		cacheTTL:   24 * time.Hour,
		maxBatch:   200,
	}
}

// Run 启动周期巡检。startup 时立刻跑一次，之后按 interval 循环。
func (c *PreCheckCron) Run(ctx context.Context) {
	c.logger.Info("precheck cron 启动",
		zap.Duration("interval", c.interval),
		zap.Duration("cache_ttl", c.cacheTTL))
	c.tickOnce(ctx)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.tickOnce(ctx)
		}
	}
}

// tickOnce 单轮巡检
func (c *PreCheckCron) tickOnce(ctx context.Context) {
	cutoff := time.Now().Add(-c.cacheTTL)
	// 先按 host_id 分组找到 online + 有过期/未检 precheck 漏洞的 host
	type hostBatch struct {
		HostID string `gorm:"column:host_id"`
		N      int64  `gorm:"column:n"`
	}
	var batches []hostBatch
	// 排除 app/container/image asset_type: SBOM 类漏洞不归 OS 包管理器,precheck 必失败
	if err := c.db.Model(&model.HostVulnerability{}).
		Select("host_id, COUNT(*) as n").
		Where(
			`status = 'unpatched' AND (
				precheck_status IN (?,?) OR precheck_checked_at IS NULL OR precheck_checked_at < ?
			) AND (asset_type IS NULL OR asset_type IN (?))`,
			model.PreCheckStatusUnchecked, model.PreCheckStatusFailed, cutoff,
			[]string{model.AssetTypeOS, model.AssetTypeMiddleware, model.AssetTypeUnknown, ""},
		).
		Group("host_id").
		Scan(&batches).Error; err != nil {
		c.logger.Error("precheck cron 查询 host 分组失败", zap.Error(err))
		return
	}
	if len(batches) == 0 {
		c.logger.Debug("precheck cron 本轮无需巡检")
		return
	}

	totalDispatched := 0
	totalHosts := 0

	for _, b := range batches {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 只对在线 host 推
		var host model.Host
		if err := c.db.Select("host_id, status").Where("host_id = ?", b.HostID).First(&host).Error; err != nil {
			continue
		}
		if host.Status != model.HostStatusOnline {
			c.logger.Debug("host 不在线，跳过 precheck",
				zap.String("host_id", b.HostID), zap.Int64("pending", b.N))
			continue
		}

		// 拉该 host 待巡检列表（带 vuln join 拿 component/fixed_version/vuln_category），上限 maxBatch
		type hvWithVuln struct {
			HostVulnID           uint   `gorm:"column:id"`
			VulnID               uint   `gorm:"column:vuln_id"`
			CveID                string `gorm:"column:cve_id"`
			Component            string `gorm:"column:component"`
			FixedVersion         string `gorm:"column:fixed_version"`
			VulnCategory         string `gorm:"column:vuln_category"`
			VulnCategoryOverride string `gorm:"column:vuln_category_override"`
		}
		var rows []hvWithVuln
		if err := c.db.Table("host_vulnerabilities AS hv").
			Select("hv.id, hv.vuln_id, v.cve_id, v.component, v.fixed_version, v.vuln_category, v.vuln_category_override").
			Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
			Where(
				`hv.host_id = ? AND hv.status = 'unpatched' AND (
					hv.precheck_status IN (?,?) OR hv.precheck_checked_at IS NULL OR hv.precheck_checked_at < ?
				)`,
				b.HostID, model.PreCheckStatusUnchecked, model.PreCheckStatusFailed, cutoff,
			).
			Limit(c.maxBatch).
			Scan(&rows).Error; err != nil {
			c.logger.Warn("拉 host pending precheck 失败",
				zap.String("host_id", b.HostID), zap.Error(err))
			continue
		}

		hostDispatched := 0
		for _, r := range rows {
			if r.Component == "" {
				continue
			}
			// P5.2: shared_lib 类要求 agent lsof 找受影响进程
			effectiveCat := r.VulnCategory
			if r.VulnCategoryOverride != "" {
				effectiveCat = r.VulnCategoryOverride
			}
			// 优先 advisory_packages 按 host OS 取精确 fixed_version
			fixedVer := ResolveFixedVersionForHost(c.db, r.CveID, r.Component, b.HostID)
			if fixedVer == "" {
				fixedVer = r.FixedVersion
			}
			payload := preCheckCronPayload{
				RequestID:              fmt.Sprintf("pc-cron-%d-%d", r.HostVulnID, time.Now().Unix()),
				HostVulnID:             r.HostVulnID,
				Component:              r.Component,
				FixedVersion:           fixedVer,
				CheckAffectedProcesses: effectiveCat == model.VulnCategorySharedLib,
			}
			body, _ := json.Marshal(payload)
			task := &grpcProto.Task{
				DataType:   9101,
				ObjectName: "remediation",
				Data:       string(body),
				Token:      payload.RequestID,
			}
			cmd := &grpcProto.Command{Tasks: []*grpcProto.Task{task}}
			if err := c.dispatcher.SendCommand(b.HostID, cmd); err != nil {
				c.logger.Warn("precheck cron dispatch 失败",
					zap.String("host_id", b.HostID),
					zap.Uint("host_vuln_id", r.HostVulnID),
					zap.Error(err))
				continue
			}
			hostDispatched++
			// 限流：每条间隔 200ms，避免 agent taskCh 堆满 drop
			time.Sleep(200 * time.Millisecond)
		}

		c.logger.Info("precheck cron host 完成",
			zap.String("host_id", b.HostID), zap.Int("dispatched", hostDispatched))
		totalDispatched += hostDispatched
		totalHosts++
		// 每 host 之间间隔 2s
		time.Sleep(2 * time.Second)
	}

	c.logger.Info("precheck cron tick 完成",
		zap.Int("hosts", totalHosts), zap.Int("dispatched", totalDispatched))
}

type preCheckCronPayload struct {
	RequestID              string `json:"request_id"`
	HostVulnID             uint   `json:"host_vuln_id"`
	Component              string `json:"component"`
	FixedVersion           string `json:"fixed_version"`
	CheckAffectedProcesses bool   `json:"check_affected_processes,omitempty"`
}

// InvalidateCacheForVuln 当某 vuln 的 component / fixed_version 更新（漏洞库同步）时，
// 将该 vuln 关联的 host_vulnerabilities.precheck_* 重置为 unchecked，触发下轮 cron 重检。
func (c *PreCheckCron) InvalidateCacheForVuln(vulnID uint) error {
	return c.db.Model(&model.HostVulnerability{}).
		Where("vuln_id = ?", vulnID).
		Updates(map[string]any{
			"precheck_status":     model.PreCheckStatusUnchecked,
			"precheck_message":    "",
			"precheck_packages":   "",
			"precheck_checked_at": nil,
		}).Error
}
