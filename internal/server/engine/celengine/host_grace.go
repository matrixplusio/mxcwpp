package celengine

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// hostCreatedAtReloadInterval 主机 created_at 快照刷新周期。
// created_at 不可变，仅为感知新上线主机而周期刷新（48h 观察窗对几分钟延迟不敏感）。
const hostCreatedAtReloadInterval = 5 * time.Minute

// reloadHostCreatedAt 一次性加载所有主机的 created_at，原子替换快照。
//
// 替代 hostInGrace 每事件一次 `SELECT created_at FROM hosts WHERE host_id=?` 的热路径 DB 查：
// 高事件量下该查询达数十万次/段，打满 MySQL 连接池（实测单查 260ms），engine goroutine 全
// 阻塞在 DB 上 → CPU 飙高 + 压垮 MySQL。created_at 不可变，全量缓存后热路径零 DB。
// 失败保留旧快照（宁可少抑制也不中断检测）。
func (g *AlertGenerator) reloadHostCreatedAt() {
	var rows []struct {
		HostID    string
		CreatedAt model.LocalTime
	}
	if err := g.db.Model(&model.Host{}).Select("host_id, created_at").Scan(&rows).Error; err != nil {
		g.log.Warn("加载主机 created_at 快照失败，保留旧快照", zap.Error(err))
		return
	}
	m := make(map[string]time.Time, len(rows))
	for _, r := range rows {
		m[r.HostID] = r.CreatedAt.Time()
	}
	g.hostCreatedAt.Store(&m)
}

// StartHostGraceReload 启动后台 goroutine 周期 reload 主机 created_at 快照（ctx 取消时退出）。
// 调用方需保证只调用一次。
func (g *AlertGenerator) StartHostGraceReload(ctx context.Context) {
	if g == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(hostCreatedAtReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.reloadHostCreatedAt()
			}
		}
	}()
}
