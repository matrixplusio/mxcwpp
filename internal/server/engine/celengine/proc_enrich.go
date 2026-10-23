package celengine

import (
	"context"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// 文件事件与网络事件只带进程号，不带「是哪个程序」。规则里凡是写了 exe / cmdline 的，
// 在这两类事件上要么恒真（exe != "dig" 对空串永远成立）、要么恒假（exe.contains(...)）。
// 这里在检测前按进程号把程序路径和命令行补上。
//
// 来源有两个，缺一不可：
//   - 进程树：由进程启动事件实时维护，新起的进程在这里；
//   - 进程清单：资产采集每小时上报的全量进程，常驻的服务进程在这里——它们在 agent
//     开始采集之前就启动了，没有启动事件，而大部分文件与网络活动恰恰来自它们。
//
// 进程树优先：进程号被复用时新进程一定有启动事件。清单最多滞后一个采集周期，
// 若 engine 恰好重启漏掉了那次启动事件，这段时间里会把活动记到原先占用该进程号的程序头上。
// 来源写进 proc_source 字段，研判时可以据此判断可信程度。
const (
	procInventoryReloadInterval = 5 * time.Minute
	// procInventoryMaxAge 超过这么久没更新的清单不用：主机已经不再上报，进程号早已面目全非。
	procInventoryMaxAge = 3 * time.Hour

	ProcSourceExec      = "exec"
	ProcSourceInventory = "inventory"
)

// serverOnlyFields 只由服务端写入的字段。事件进来时先清掉：告警详情里会原样带出它们，
// 研判的人分不清是服务端写的还是上报方带进来的。
var serverOnlyFields = []string{"proc_source", "declared_severity"}

// StripServerOnlyFields 去掉事件里本该只由服务端写入的字段。必须在其它处理之前调用。
func StripServerOnlyFields(fields map[string]string) {
	for _, k := range serverOnlyFields {
		delete(fields, k)
	}
}

type procInfo struct {
	exe     string
	cmdline string
}

type procEnrichStats struct {
	fromTree      atomic.Int64
	fromInventory atomic.Int64
	miss          atomic.Int64
}

// StartProcInventoryReload 加载并周期刷新进程清单快照，同时定期把补全率打进日志。
func (e *Engine) StartProcInventoryReload(ctx context.Context) {
	if e == nil || e.db == nil {
		return
	}
	e.reloadProcInventory()
	go func() {
		ticker := time.NewTicker(procInventoryReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.reloadProcInventory()
				e.logProcEnrichStats()
			}
		}
	}()
}

func (e *Engine) reloadProcInventory() {
	type row struct {
		HostID  string
		PID     string `gorm:"column:pid"`
		Exe     string
		Cmdline string
	}
	var rows []row
	cutoff := time.Now().Add(-procInventoryMaxAge)
	if err := e.db.Table("processes").Select("host_id, pid, exe, cmdline").
		Where("collected_at >= ? AND exe <> ''", cutoff).Find(&rows).Error; err != nil {
		// 读失败沿用上一份快照。
		e.log.Warn("进程清单加载失败", zap.Error(err))
		return
	}
	snap := make(map[string]map[string]procInfo, 512)
	for i := range rows {
		r := &rows[i]
		host := snap[r.HostID]
		if host == nil {
			host = make(map[string]procInfo, 256)
			snap[r.HostID] = host
		}
		host[r.PID] = procInfo{exe: r.Exe, cmdline: r.Cmdline}
	}
	e.procInventory.Store(&snap)
}

func (e *Engine) logProcEnrichStats() {
	tree, inv, miss := e.procStats.fromTree.Swap(0), e.procStats.fromInventory.Swap(0), e.procStats.miss.Swap(0)
	total := tree + inv + miss
	if total == 0 {
		return
	}
	e.log.Info("事件进程信息补全统计",
		zap.Int64("events", total),
		zap.Int64("from_exec", tree),
		zap.Int64("from_inventory", inv),
		zap.Int64("miss", miss),
		zap.Float64("resolved_pct", float64(tree+inv)*100/float64(total)))
}

// EnrichProcess 给不带程序信息的事件按进程号补上 exe 与 cmdline，直接写进 fields。
// 进程事件自带这些字段，不处理；查不到时保持为空，规则用 exe_known 区分「不是」与「不知道」。
func (e *Engine) EnrichProcess(agentID, hostID string, dataType int32, fields map[string]string) {
	if e == nil || dataType == 3000 || fields["exe"] != "" {
		return
	}
	pid := fields["pid"]
	if pid == "" || pid == "0" {
		return
	}
	if e.procTree != nil && agentID != "" {
		if info, ok := e.procTree.Lookup(agentID, pid); ok && info.exe != "" {
			applyProcInfo(fields, info, ProcSourceExec)
			e.procStats.fromTree.Add(1)
			return
		}
	}
	if snap := e.procInventory.Load(); snap != nil {
		if host := (*snap)[hostID]; host != nil {
			if info, ok := host[pid]; ok {
				applyProcInfo(fields, info, ProcSourceInventory)
				e.procStats.fromInventory.Add(1)
				return
			}
		}
	}
	e.procStats.miss.Add(1)
}

func applyProcInfo(fields map[string]string, info procInfo, source string) {
	fields["exe"] = info.exe
	if fields["cmdline"] == "" {
		fields["cmdline"] = info.cmdline
	}
	fields["proc_source"] = source
}
