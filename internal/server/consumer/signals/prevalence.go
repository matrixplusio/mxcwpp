package signals

import (
	"context"
	"math"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	// prevalenceInterval 普遍性统计的周期。
	prevalenceInterval = time.Hour
	// prevalenceMinShare 覆盖不到这个比例的组合不写表：风险累积查不到时按 1 计，与写进去一样。
	prevalenceMinShare = 0.1
)

// RunPrevalence 每小时统计一次「规则 + 程序」在近 7 天里出现在多少台登记主机上，写入
// signal_prevalence，供 engine 的风险累积降低普遍行为的分值。
//
// 只数主机表里登记过的主机：信号里的主机号来自上报方，若把未登记的也算进去，伪造大量
// 主机号就能把一个恶意程序刷成「很普遍」，从而压低它的分值。stage 为空的行是 engine 升级前
// 回补进来的，规则号分不清 CEL 还是攻击链，不参与统计。
func RunPrevalence(ctx context.Context, conn chdriver.Conn, db *gorm.DB, logger *zap.Logger) {
	if conn == nil || db == nil {
		return
	}
	run := func() {
		if err := computePrevalence(ctx, conn, db); err != nil {
			prevalenceFailures.Inc()
			logger.Warn("信号普遍性统计失败，engine 沿用上一次的结果", zap.Error(err))
			return
		}
		prevalenceLastSuccess.SetToCurrentTime()
	}
	run()
	t := time.NewTicker(prevalenceInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func computePrevalence(ctx context.Context, conn chdriver.Conn, db *gorm.DB) error {
	var hosts []string
	if err := db.Model(&model.Host{}).Pluck("host_id", &hosts).Error; err != nil {
		return err
	}
	if len(hosts) == 0 {
		return nil
	}
	minHosts := int(math.Ceil(prevalenceMinShare * float64(len(hosts))))
	qctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	rows, err := conn.Query(qctx, `SELECT rule_id, substring(exe, 1, 255) AS e, uniqExact(host_id) AS h
		FROM signals
		WHERE bucket >= now() - INTERVAL 7 DAY AND stage != '' AND exe != '' AND host_id IN ?
		GROUP BY rule_id, e HAVING h >= ?`, hosts, uint64(minHosts))
	if err != nil {
		return err
	}
	defer rows.Close()
	var out []model.SignalPrevalence
	for rows.Next() {
		var rule, exe string
		var h uint64
		if err := rows.Scan(&rule, &exe, &h); err != nil {
			return err
		}
		out = append(out, model.SignalPrevalence{RuleID: rule, Exe: exe, Hosts: int(h), TotalHosts: len(hosts)})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// 整表替换：上一轮有、这一轮没有的组合必须删掉，否则一个曾经普遍、如今罕见的程序会一直被降分。
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&model.SignalPrevalence{}).Error; err != nil {
			return err
		}
		if len(out) == 0 {
			return nil
		}
		return tx.CreateInBatches(out, 500).Error
	})
}
