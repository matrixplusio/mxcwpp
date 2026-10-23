// Package metrics 提供 AgentCenter 侧的 Prometheus Gauge 指标导出
// 与 Elkeid 架构一致：AC 收到心跳后更新 in-process Gauge，
// Prometheus 通过 /metrics 端点抓取，无需额外 Kafka 路径。
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	hostCPUUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_host_cpu_usage",
		Help: "Host CPU usage percentage",
	}, []string{"host_id", "hostname"})

	hostMemUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_host_mem_usage",
		Help: "Host memory usage percentage",
	}, []string{"host_id", "hostname"})

	hostDiskUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_host_disk_usage",
		Help: "Host disk usage percentage",
	}, []string{"host_id", "hostname"})

	hostNetIn = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_host_net_in",
		Help: "Host network inbound bytes per heartbeat interval",
	}, []string{"host_id", "hostname"})

	hostNetOut = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_host_net_out",
		Help: "Host network outbound bytes per heartbeat interval",
	}, []string{"host_id", "hostname"})

	hostDiskRead = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_host_disk_read_bytes",
		Help: "Host disk read bytes per heartbeat interval",
	}, []string{"host_id", "hostname"})

	hostDiskWrite = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_host_disk_write_bytes",
		Help: "Host disk write bytes per heartbeat interval",
	}, []string{"host_id", "hostname"})

	agentCPUUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_agent_cpu_usage",
		Help: "Agent process CPU usage percentage",
	}, []string{"host_id", "hostname"})

	agentMemRSS = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_agent_mem_rss",
		Help: "Agent process resident memory in bytes",
	}, []string{"host_id", "hostname"})

	agentMemPercent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mxcwpp_agent_mem_percent",
		Help: "Agent process memory usage as percentage of total system memory",
	}, []string{"host_id", "hostname"})
)

// Update 根据心跳数据更新指定主机的所有 Gauge。
// 支持的 key：cpu_usage, mem_usage, disk_usage, net_in, net_out,
// disk_read_bytes, disk_write_bytes, agent_cpu_usage, agent_mem_rss。
func Update(hostID, hostname string, m map[string]float64) {
	labels := prometheus.Labels{"host_id": hostID, "hostname": hostname}
	if v, ok := m["cpu_usage"]; ok {
		hostCPUUsage.With(labels).Set(v)
	}
	if v, ok := m["mem_usage"]; ok {
		hostMemUsage.With(labels).Set(v)
	}
	if v, ok := m["disk_usage"]; ok {
		hostDiskUsage.With(labels).Set(v)
	}
	if v, ok := m["net_in"]; ok {
		hostNetIn.With(labels).Set(v)
	}
	if v, ok := m["net_out"]; ok {
		hostNetOut.With(labels).Set(v)
	}
	if v, ok := m["disk_read_bytes"]; ok {
		hostDiskRead.With(labels).Set(v)
	}
	if v, ok := m["disk_write_bytes"]; ok {
		hostDiskWrite.With(labels).Set(v)
	}
	if v, ok := m["agent_cpu_usage"]; ok {
		agentCPUUsage.With(labels).Set(v)
	}
	if v, ok := m["agent_mem_rss"]; ok {
		agentMemRSS.With(labels).Set(v)
	}
	if v, ok := m["agent_mem_percent"]; ok {
		agentMemPercent.With(labels).Set(v)
	}
}

// Delete 在 Agent 离线时删除其对应的 Gauge label，避免 stale 数据。
func Delete(hostID, hostname string) {
	labels := prometheus.Labels{"host_id": hostID, "hostname": hostname}
	hostCPUUsage.Delete(labels)
	hostMemUsage.Delete(labels)
	hostDiskUsage.Delete(labels)
	hostNetIn.Delete(labels)
	hostNetOut.Delete(labels)
	hostDiskRead.Delete(labels)
	hostDiskWrite.Delete(labels)
	agentCPUUsage.Delete(labels)
	agentMemRSS.Delete(labels)
	agentMemPercent.Delete(labels)
}
