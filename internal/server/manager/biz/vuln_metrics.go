// Package biz - vuln metrics
//
// 商业级 CWPP 必须暴露的 Prometheus metrics（用于 Grafana dashboard + alert）：
//
//	mxsec_vuln_total{source,confidence,severity}  — 当前漏洞总数
//	mxsec_remediation_task_total{status,severity} — 修复任务计数
//	mxsec_remediation_task_duration_seconds       — 修复耗时分布
//	mxsec_vuln_import_errors_total{source}        — 数据源拉取错误数
//	mxsec_vuln_integrity_check_failures_total     — 数据完整性反查失败数
package biz

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// VulnMetrics 集中管理所有 vuln/remediation 相关 Prometheus metrics。
var VulnMetrics = struct {
	VulnTotal               *prometheus.GaugeVec
	RemediationTaskTotal    *prometheus.CounterVec
	RemediationTaskDuration *prometheus.HistogramVec
	VulnImportErrors        *prometheus.CounterVec
	VulnIntegrityFailures   prometheus.Counter
}{
	VulnTotal: promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxsec_vuln_total",
		Help: "当前漏洞总数，按 source/confidence/severity 维度。",
	}, []string{"source", "confidence", "severity"}),

	RemediationTaskTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxsec_remediation_task_total",
		Help: "修复任务计数，按 status/severity 维度。",
	}, []string{"status", "severity"}),

	RemediationTaskDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mxsec_remediation_task_duration_seconds",
		Help:    "修复任务端到端耗时分布（从 dispatched 到 completed/failed）。",
		Buckets: []float64{5, 15, 30, 60, 120, 300, 600, 1800, 3600}, // 5s 到 1h
	}, []string{"status", "pkg_manager"}),

	VulnImportErrors: promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxsec_vuln_import_errors_total",
		Help: "vuln 数据源 import 错误计数（按 source 维度）。",
	}, []string{"source"}),

	VulnIntegrityFailures: promauto.NewCounter(prometheus.CounterOpts{
		Name: "mxsec_vuln_integrity_check_failures_total",
		Help: "vuln 数据完整性反查失败数（cron 抽样比对 OS advisory）。",
	}),
}

// 推荐 alert rules（写入 prometheus rule 文件）：
//
//	- alert: VulnImportFailingRate
//	  expr: rate(mxsec_vuln_import_errors_total[5m]) > 0.1
//	  for: 10m
//	  annotations:
//	    summary: "vuln 数据源 {{ $labels.source }} 5min import 错误率 > 0.1/s"
//
//	- alert: RemediationSuccessRateLow
//	  expr: |
//	    sum(rate(mxsec_remediation_task_total{status="completed"}[1h]))
//	      / sum(rate(mxsec_remediation_task_total[1h])) < 0.95
//	  for: 30m
//	  annotations:
//	    summary: "1h 修复成功率 < 95%（商业级 SLA 阈值）"
//
//	- alert: VulnDataIntegrityFailing
//	  expr: increase(mxsec_vuln_integrity_check_failures_total[24h]) > 1
//	  annotations:
//	    summary: "24h 数据完整性反查发现失败，疑似 vuln DB 数据偏离上游 advisory"
