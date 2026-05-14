// Package migration 提供数据库迁移功能
package migration

import (
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// indexDef 定义一个索引
type indexDef struct {
	table string
	name  string
	sql   string // ALTER TABLE 形式，MySQL 兼容
}

// AddPerformanceIndexes 添加所有性能优化索引（幂等，先检查再创建）
func AddPerformanceIndexes(db *gorm.DB, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Info("开始添加性能优化索引")

	indexes := []indexDef{
		// ---- scan_results ----
		{
			table: "scan_results",
			name:  "idx_scan_results_host_rule_checked",
			sql:   "ALTER TABLE scan_results ADD INDEX idx_scan_results_host_rule_checked (host_id, rule_id, checked_at)",
		},
		{
			table: "scan_results",
			name:  "idx_scan_results_host_checked",
			sql:   "ALTER TABLE scan_results ADD INDEX idx_scan_results_host_checked (host_id, checked_at)",
		},
		{
			table: "scan_results",
			name:  "idx_scan_results_host_status_severity",
			sql:   "ALTER TABLE scan_results ADD INDEX idx_scan_results_host_status_severity (host_id, status, severity)",
		},
		{
			// dashboard: calculateBaselinePercentages — 全表聚合加速
			table: "scan_results",
			name:  "idx_scan_results_status_severity",
			sql:   "ALTER TABLE scan_results ADD INDEX idx_scan_results_status_severity (status, severity)",
		},
		{
			// dashboard: getBaselineRisksTop3 JOIN
			table: "scan_results",
			name:  "idx_scan_results_policy_status_severity",
			sql:   "ALTER TABLE scan_results ADD INDEX idx_scan_results_policy_status_severity (policy_id, status, severity)",
		},
		{
			// dashboard: baselineFailCount WHERE checked_at >= ?
			table: "scan_results",
			name:  "idx_scan_results_checked_at",
			sql:   "ALTER TABLE scan_results ADD INDEX idx_scan_results_checked_at (checked_at)",
		},

		// ---- hosts ----
		{
			table: "hosts",
			name:  "idx_hosts_status",
			sql:   "ALTER TABLE hosts ADD INDEX idx_hosts_status (status)",
		},
		{
			// dashboard: GROUP BY is_container, status（覆盖索引）
			table: "hosts",
			name:  "idx_hosts_is_container_status",
			sql:   "ALTER TABLE hosts ADD INDEX idx_hosts_is_container_status (is_container, status)",
		},
		{
			// hosts list: ORDER BY last_heartbeat DESC
			table: "hosts",
			name:  "idx_hosts_last_heartbeat",
			sql:   "ALTER TABLE hosts ADD INDEX idx_hosts_last_heartbeat (last_heartbeat)",
		},
		{
			table: "hosts",
			name:  "idx_hosts_created_at",
			sql:   "ALTER TABLE hosts ADD INDEX idx_hosts_created_at (created_at)",
		},

		// ---- alerts ----
		{
			// GetAlertStatistics: GROUP BY status
			table: "alerts",
			name:  "idx_alerts_status",
			sql:   "ALTER TABLE alerts ADD INDEX idx_alerts_status (status)",
		},
		{
			// GetAlertStatistics: WHERE status=active GROUP BY severity
			table: "alerts",
			name:  "idx_alerts_status_severity",
			sql:   "ALTER TABLE alerts ADD INDEX idx_alerts_status_severity (status, severity)",
		},
		{
			// ListAlerts: ORDER BY last_seen_at DESC
			table: "alerts",
			name:  "idx_alerts_last_seen_at",
			sql:   "ALTER TABLE alerts ADD INDEX idx_alerts_last_seen_at (last_seen_at)",
		},

		// ---- scan_tasks ----
		{
			table: "scan_tasks",
			name:  "idx_scan_tasks_status_created",
			sql:   "ALTER TABLE scan_tasks ADD INDEX idx_scan_tasks_status_created (status, created_at)",
		},

		// ---- vulnerabilities ----
		{
			table: "vulnerabilities",
			name:  "idx_vulns_status_severity",
			sql:   "ALTER TABLE vulnerabilities ADD INDEX idx_vulns_status_severity (status, severity)",
		},
		{
			table: "vulnerabilities",
			name:  "idx_vulns_discovered_at",
			sql:   "ALTER TABLE vulnerabilities ADD INDEX idx_vulns_discovered_at (discovered_at)",
		},

		// ---- host_vulnerabilities ----
		{
			table: "host_vulnerabilities",
			name:  "idx_hv_vuln_status",
			sql:   "ALTER TABLE host_vulnerabilities ADD INDEX idx_hv_vuln_status (vuln_id, status)",
		},
		{
			table: "host_vulnerabilities",
			name:  "idx_hv_host_status",
			sql:   "ALTER TABLE host_vulnerabilities ADD INDEX idx_hv_host_status (host_id, status)",
		},

		// ---- kube_alarms ----
		{
			// kube_alarm_filter: 按 fingerprint+status 查找 pending 告警实现去重 UPSERT
			table: "kube_alarms",
			name:  "idx_kube_alarm_fp_status",
			sql:   "ALTER TABLE kube_alarms ADD INDEX idx_kube_alarm_fp_status (fingerprint, status)",
		},

		// ---- command_ack_records ----
		{
			table: "command_ack_records",
			name:  "idx_cmdack_host_type",
			sql:   "ALTER TABLE command_ack_records ADD INDEX idx_cmdack_host_type (host_id, command_type)",
		},
		{
			table: "command_ack_records",
			name:  "idx_cmdack_acked_at",
			sql:   "ALTER TABLE command_ack_records ADD INDEX idx_cmdack_acked_at (acknowledged_at)",
		},
	}

	migrator := db.Migrator()
	created, skipped := 0, 0
	for _, idx := range indexes {
		// HasIndex 检查索引是否已存在（MySQL 兼容）
		if migrator.HasIndex(idx.table, idx.name) {
			skipped++
			continue
		}
		if err := db.Exec(idx.sql).Error; err != nil {
			// 忽略重复键错误（并发创建竞争），记录其他错误
			logger.Warn("创建索引失败（跳过）", zap.String("index", idx.name), zap.Error(err))
			continue
		}
		logger.Info("索引已创建", zap.String("index", idx.name))
		created++
	}

	logger.Info("性能优化索引完成", zap.Int("created", created), zap.Int("skipped", skipped))
	return nil
}
