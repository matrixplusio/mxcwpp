package scheduler

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// MySQL 侧保留清理参数。
const (
	mysqlRetentionInterval = 6 * time.Hour // 清理周期
	mysqlRetentionBatch    = 5000          // 单批删除行数，避免长事务锁表
	mysqlRetentionMaxLoops = 200           // 单表单轮最多删 100 万行，防止一轮跑太久
)

// retentionTarget 描述一张需要在 MySQL 侧按保留期清理的表。
type retentionTarget struct {
	// Table 是 MySQL 表名。
	Table string
	// TimeColumn 是判定过期用的时间列。
	TimeColumn string
	// PolicyKey 对应 retention_policies.ch_table，从中读保留天数。
	PolicyKey string
	// FallbackDays 是 retention_policies 里查不到该策略时的兜底天数。
	FallbackDays int
	// ScopedToLiveHosts 为真时，只清理"仍在上报的主机"的历史行。
	//
	// 见 mysqlRetentionTargets 的说明：这是防止把停报主机的最后状态删掉的护栏。
	// 表必须有 host_id 列才能开。
	ScopedToLiveHosts bool
}

// mysqlRetentionTargets 是清理白名单。
//
// 为什么需要这份清理：retention_policies 的保留期只会被下发成 ClickHouse 的
// TABLE TTL（见 model/retention_policy.go 的注释与 admin_data_config 的实现），
// 而 feature_flag.data_source.* 默认全是 mysql —— 数据写在 MySQL，清理只对
// ClickHouse 生效，两边没有任何校验把这个缺口暴露出来。storyline_events 因此
// 涨到 亿级行、数百 GB 写满存储节点，级联拖垮平台（2026-08）。
//
// 为什么是白名单而不是遍历所有表：这些表的语义并不一致，判错就是删数据。
// 实测 kernel_modules 绝大多数主机只存在**一个** collected_at ——
// 它是"当前快照"（覆盖式），不是历史流水。对它按时间删，等于把资产数据直接抹掉，
// 而且除非主机重新上报否则不会再生。services 的分布同样混杂（每主机 1~8 份）。
// 这两张表要的是"每主机保留最近 N 份"，与本任务的"删除 N 天前"不是一个语义，
// 故不纳入，留待单独实现。
//
// ScopedToLiveHosts 按表的语义决定，判据是"这张表里某主机的最新几行，是不是该主机
// 当前状态的唯一记录"：
//
//   - 状态型（host_metrics / ports）：是。主机停止上报后，它的行会随时间逐条越过
//     保留期，直到这台主机的最后一份画像彻底消失——而停报主机恰恰是排查时最需要
//     数据的那些。故只清理仍在上报的主机。
//   - 事件流型（storyline_events / fim_events / audit_logs）：否。这里没有"当前状态"，
//     只有按时间排列的记录，保留期本身就是"多久之前的记录不再需要"这个产品决定，
//     它对活主机和死主机同样成立。若也按活跃度豁免，已下架但未删除的主机会永久
//     囤积数据，反而变成新的增长源。
var mysqlRetentionTargets = []retentionTarget{
	// --- 事件流：按保留期直接清理 ---
	{Table: "storyline_events", TimeColumn: "timestamp", PolicyKey: "storyline_events", FallbackDays: 90},
	{Table: "fim_events", TimeColumn: "detected_at", PolicyKey: "fim_events", FallbackDays: 30},
	// 审计日志：合规留存，且无 host 维度。
	{Table: "audit_logs", TimeColumn: "created_at", PolicyKey: "audit_log", FallbackDays: 180},

	// --- 状态型：只清理仍在上报的主机 ---
	// 时序指标：每主机每采集周期一行，可达千万行量级。
	{Table: "host_metrics", TimeColumn: "collected_at", PolicyKey: "host_metrics", FallbackDays: 30, ScopedToLiveHosts: true},
	// 端口快照历史：实测存在大量不同 collected_at，确为逐次追加，但每主机最新一批
	// 就是它当前的监听端口画像。
	{Table: "ports", TimeColumn: "collected_at", PolicyKey: "ports_snapshots", FallbackDays: 30, ScopedToLiveHosts: true},
}

// StartMySQLRetentionScheduler 启动 MySQL 侧保留期清理调度器。
func StartMySQLRetentionScheduler(db *gorm.DB, logger *zap.Logger) {
	ticker := time.NewTicker(mysqlRetentionInterval)
	defer ticker.Stop()

	logger.Info("MySQL 保留清理调度器已启动",
		zap.Duration("interval", mysqlRetentionInterval),
		zap.Int("tables", len(mysqlRetentionTargets)))

	processMySQLRetention(db, logger)
	for range ticker.C {
		processMySQLRetention(db, logger)
	}
}

// processMySQLRetention 执行一轮清理。
func processMySQLRetention(db *gorm.DB, logger *zap.Logger) {
	days := loadRetentionDays(db, logger)

	for _, tgt := range mysqlRetentionTargets {
		d := tgt.FallbackDays
		if v, ok := days[tgt.PolicyKey]; ok && v > 0 {
			d = v
		}
		deleted, err := pruneTable(db, tgt, d)
		if err != nil {
			logger.Warn("MySQL 保留清理失败",
				zap.String("table", tgt.Table), zap.Int("retention_days", d), zap.Error(err))
			continue
		}
		if deleted > 0 {
			logger.Info("已清理过期数据",
				zap.String("table", tgt.Table),
				zap.Int64("deleted", deleted),
				zap.Int("retention_days", d))
		}
	}
}

// loadRetentionDays 读取 retention_policies，返回 ch_table → 保留天数。
// 读失败时返回空 map，各表回落到 FallbackDays。
func loadRetentionDays(db *gorm.DB, logger *zap.Logger) map[string]int {
	var policies []model.RetentionPolicy
	if err := db.Find(&policies).Error; err != nil {
		logger.Warn("读取 retention_policies 失败，本轮使用兜底保留天数", zap.Error(err))
		return nil
	}
	out := make(map[string]int, len(policies))
	for _, p := range policies {
		out[p.CHTable] = p.RetentionDays
	}
	return out
}

// pruneStatement 构造删除语句的主体（不含 LIMIT）与参数。
//
// 与批处理分开，是为了让"删哪些行"这个判断能被单独验证：
// 批处理依赖 MySQL 的 DELETE ... LIMIT，sqlite 不支持该语法，
// 若把两者揉在一起，最危险的那条语义（停报主机的数据不能删）就只能在真库上测。
func pruneStatement(tgt retentionTarget, cutoff time.Time) (string, []any) {
	sql := fmt.Sprintf("DELETE FROM `%s` WHERE `%s` < ?", tgt.Table, tgt.TimeColumn)
	args := []any{cutoff}
	if tgt.ScopedToLiveHosts {
		// 只清理仍在上报的主机；停报主机的最后状态原样保留。
		sql += " AND host_id IN (SELECT host_id FROM hosts WHERE last_heartbeat >= ?)"
		args = append(args, cutoff)
	}
	return sql, args
}

// pruneTable 分批删除单表的过期行，返回删除总数。
//
// 分批的理由与 scan_results 清理一致：一次性删几百万行会长时间持锁，
// 把在线查询一起拖住。达到 mysqlRetentionMaxLoops 后本轮收手，下一轮继续。
func pruneTable(db *gorm.DB, tgt retentionTarget, days int) (int64, error) {
	if days <= 0 {
		return 0, fmt.Errorf("保留天数必须为正，得到 %d", days)
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	stmt, args := pruneStatement(tgt, cutoff)
	stmt += " LIMIT ?"

	var total int64
	for range mysqlRetentionMaxLoops {
		res := db.Exec(stmt, append(append([]any{}, args...), mysqlRetentionBatch)...)
		if res.Error != nil {
			return total, res.Error
		}
		total += res.RowsAffected
		if res.RowsAffected < int64(mysqlRetentionBatch) {
			break
		}
	}
	return total, nil
}
