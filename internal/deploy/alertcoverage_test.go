package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCriticalMetricsHaveAlerts 关键指标必须有对应告警规则。
//
// 平台此前的典型形态是"埋了点、没人报警"：agent 丢事件、engine 背压丢弃、
// Stage 报错、消息处理失败四个指标都在采集，图表上看得见，却没有任何规则会把人叫醒。
// 数据在丢而无人知晓，与没有这些指标没有区别——审计把这种叫"可观测空壳"。
//
// 本测试把清单钉住：新增关键指标必须同时补告警，否则失败。
func TestCriticalMetricsHaveAlerts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "deploy", "config", "prometheus-rules.yml"))
	if err != nil {
		t.Skipf("读取告警规则失败: %v", err)
	}
	rules := string(data)

	// 每一项都代表一种"数据在丢或能力已失效"的状态，必须有人被叫醒。
	critical := map[string]string{
		"mxcwpp_agent_event_dropped_total":               "Agent 丢事件 = 该主机检测盲区",
		"mxcwpp_engine_backpressure_drop_total":          "Engine 背压丢弃 = 漏检",
		"mxcwpp_engine_stage_errors_total":               "Stage 持续报错 = 该项检测能力静默失效",
		"mxcwpp_consumer_dlq_write_failures_total":       "DLQ 写失败 = 消息不可恢复地丢失",
		"mxcwpp_consumer_ch_write_errors_total":          "CH 写失败 = offset 暂停推进，需人工介入",
		"mxcwpp_ac_unrouted_datatype_total":              "DataType 未登记路由 = 消息被静默忽略",
		"mxcwpp_vulnsync_last_success_timestamp_seconds": "漏洞库停更 = 界面显示的是旧数据",
		"mxcwpp_incident_sla_breached":                   "事件超时无人认领 = 检测到了但没人处置",
		"mxcwpp_incident_unowned":                        "无主事件堆积 = 即将变成超时",
		"mxcwpp_anomaly_reference_baseline_ready":        "参照基线缺失 = ML 训练投毒防护未生效",
		"mxcwpp_anomaly_model_version":                   "模型版本停滞 = 模型停止学习，分数越来越不反映当前环境",
		"mxcwpp_anomaly_training_hosts":                  "训练集变窄 = 模型向少数主机收敛，其余主机的正常行为被判异常",
		"mxcwpp_anomaly_score_flush_failed_total":        "异常分落库失败 = ranking 档静默失效但显示已启用",
		"mxcwpp_engine_abnormal_login_hosts_graduated":   "无主机走完学习期 = 异常登录检测一直静默，与没接线无异",
	}

	for metric, why := range critical {
		if !strings.Contains(rules, metric) {
			t.Errorf("关键指标 %s 没有任何告警规则引用\n  原因: %s\n"+
				"  埋点而不告警等于没有埋点——请在 deploy/config/prometheus-rules.yml 补规则。",
				metric, why)
		}
	}
}
