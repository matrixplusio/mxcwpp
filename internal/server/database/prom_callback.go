// Package database — gorm Prometheus 埋点 callback。
//
// 在每次 SQL 操作（query/exec/create/update/delete/row）完成后，记录：
//   - mxcwpp_db_query_duration_seconds{operation, table}  histogram
//
// 用途：Manager 视角的 DB QPS/p99 真实可见，替代 mysqld_exporter
// （后者反映整个 MySQL 实例，可能被其他应用共用，不准确反映 mxcwpp 负载）。
package database

import (
	"time"

	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/metrics"
)

const promStartKey = "mxcwpp:db:prom:start"

// RegisterPromCallback 在 gorm.DB 上注册 Prometheus 埋点 callback。
// 应在 database.Init() 成功后立即调用。
func RegisterPromCallback(db *gorm.DB) error {
	if db == nil {
		return nil
	}

	cb := db.Callback()
	if err := cb.Query().Before("gorm:query").Register("mxcwpp:prom:before:query", promBefore); err != nil {
		return err
	}
	if err := cb.Query().After("gorm:query").Register("mxcwpp:prom:after:query", makePromAfter("query")); err != nil {
		return err
	}
	if err := cb.Create().Before("gorm:create").Register("mxcwpp:prom:before:create", promBefore); err != nil {
		return err
	}
	if err := cb.Create().After("gorm:create").Register("mxcwpp:prom:after:create", makePromAfter("create")); err != nil {
		return err
	}
	if err := cb.Update().Before("gorm:update").Register("mxcwpp:prom:before:update", promBefore); err != nil {
		return err
	}
	if err := cb.Update().After("gorm:update").Register("mxcwpp:prom:after:update", makePromAfter("update")); err != nil {
		return err
	}
	if err := cb.Delete().Before("gorm:delete").Register("mxcwpp:prom:before:delete", promBefore); err != nil {
		return err
	}
	if err := cb.Delete().After("gorm:delete").Register("mxcwpp:prom:after:delete", makePromAfter("delete")); err != nil {
		return err
	}
	if err := cb.Row().Before("gorm:row").Register("mxcwpp:prom:before:row", promBefore); err != nil {
		return err
	}
	if err := cb.Row().After("gorm:row").Register("mxcwpp:prom:after:row", makePromAfter("row")); err != nil {
		return err
	}
	if err := cb.Raw().Before("gorm:raw").Register("mxcwpp:prom:before:raw", promBefore); err != nil {
		return err
	}
	if err := cb.Raw().After("gorm:raw").Register("mxcwpp:prom:after:raw", makePromAfter("raw")); err != nil {
		return err
	}
	return nil
}

func promBefore(tx *gorm.DB) {
	tx.InstanceSet(promStartKey, time.Now())
}

func makePromAfter(operation string) func(*gorm.DB) {
	return func(tx *gorm.DB) {
		startAny, ok := tx.InstanceGet(promStartKey)
		if !ok {
			return
		}
		start, ok := startAny.(time.Time)
		if !ok {
			return
		}
		elapsed := time.Since(start).Seconds()

		table := tx.Statement.Table
		if table == "" {
			table = "unknown"
		}
		metrics.RecordDBQueryDuration(operation, table, elapsed)
	}
}
