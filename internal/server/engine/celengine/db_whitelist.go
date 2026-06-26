package celengine

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// dbWhitelistReloadInterval DB 告警白名单快照刷新周期。
// 自动调优采纳的 exception 通过此周期生效（不要求实时）。
const dbWhitelistReloadInterval = 5 * time.Minute

// reloadDBWhitelist 从 alert_whitelists 表加载有 exe/cmdline/host 约束的条目，原子替换快照。
//
// 仅取有具体收窄维度的条目（排除纯 source_ip_cidr 的 ScanDetector 条目），减小热路径匹配集。
// 失败保留旧快照（宁可少抑制也不要中断检测）。
func (g *AlertGenerator) reloadDBWhitelist() {
	var rows []model.AlertWhitelist
	if err := g.db.
		Where("(exe IS NOT NULL AND exe <> '') OR (cmdline IS NOT NULL AND cmdline <> '') OR (host_id IS NOT NULL AND host_id <> '')").
		Find(&rows).Error; err != nil {
		g.log.Warn("加载 DB 告警白名单失败，保留旧快照", zap.Error(err))
		return
	}
	g.dbWhitelist.Store(&rows)
}

// StartWhitelistReload 启动后台 goroutine 周期 reload DB 白名单（ctx 取消时退出）。
// 调用方需保证只调用一次。
func (g *AlertGenerator) StartWhitelistReload(ctx context.Context) {
	if g == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(dbWhitelistReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.reloadDBWhitelist()
			}
		}
	}()
}

// matchDBWhitelist 判断告警是否命中 DB 白名单（exe/cmdline/host 维度）。返回 (命中, reason)。
// 零锁读原子快照；快照未就绪时不抑制。
func (g *AlertGenerator) matchDBWhitelist(ruleID, hostID, category, severity string, fields map[string]string) (bool, string) {
	snap := g.dbWhitelist.Load()
	if snap == nil {
		return false, ""
	}
	for i := range *snap {
		w := &(*snap)[i]
		if w.MatchesAlert(ruleID, hostID, category, severity, fields) {
			return true, fmt.Sprintf("db_whitelist:%d", w.ID)
		}
	}
	return false, ""
}
