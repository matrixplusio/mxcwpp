// Package model - ch_sync.go ClickHouse 同步辅助。
//
// 设计：
//   - 注入全局 ChConn（manager / consumer / agentcenter 启动时各自注入一次）
//   - Alert / Vulnerability / HostVulnerability 三类 model 在 AfterCreate /
//     AfterUpdate GORM hook 内调用对应 syncXxxToCH() 自动写 CH
//   - 写入经 ch_batch.go 的缓冲攒批后发出：逐行 INSERT 会让 ClickHouse
//     每行产出一个 part，合并压力全落在存储节点上
//   - 写 CH 失败仅 log，不阻塞 MySQL 事务（事务已 commit 后才触发 hook）
//
// 这样所有 200+ 处 db.Create/Save/Updates 调用自动获得双写能力，无需手改业务代码。
package model

import (
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
)

var (
	chConn     chdriver.Conn
	chSyncLog  *zap.Logger
	chSyncOpen bool
)

// SetClickHouse 注入 ClickHouse 连接。在 server 启动时（setup/init）调用一次。
// 传 nil 等于禁用同步（hook 自动 no-op）。
func SetClickHouse(c chdriver.Conn, logger *zap.Logger) {
	chConn = c
	chSyncLog = logger
	chSyncOpen = c != nil
	if chSyncOpen {
		// 与连接注入绑死：能入队就一定已经启动过冲刷器，
		// 不存在「写了缓冲但没人冲刷」这种半接线状态。
		startCHFlusher()
	}
}

// nowVersion 用 UnixNano 作为 ReplacingMergeTree 版本号，保证单调递增。
func nowVersion() uint64 {
	return uint64(time.Now().UnixNano())
}

// chLogError 容错记录 CH 写入失败（不抛错，业务路径继续）。
func chLogError(table string, err error) {
	if chSyncLog != nil {
		chSyncLog.Warn("ClickHouse 同步失败",
			zap.String("table", table),
			zap.Error(err),
		)
	}
}

// asTime 把 LocalTime 转 time.Time，*LocalTime 为 nil 时返回零值。
func asTime(t *LocalTime) time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Time(*t)
}
