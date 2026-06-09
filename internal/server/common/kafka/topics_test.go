package kafka

import "testing"

func TestRouteDataType_V2Topics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		dataType int32
		want     string
	}{
		{"engine_alert", 11050, TopicEngineAlert},
		{"engine_storyline", 11150, TopicEngineStoryline},
		{"engine_command", 11850, TopicEngineCommand},
		{"engine_feedback", 11950, TopicEngineFeedback},
		{"vuln_advisory", 12050, TopicVulnAdvisory},
		{"llm_audit", 13050, TopicLLMAudit},
		{"metering_usage", 14050, TopicMeteringUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RouteDataType(tc.dataType, "")
			if got != tc.want {
				t.Fatalf("RouteDataType(%d): want %q, got %q", tc.dataType, tc.want, got)
			}
		})
	}
}

func TestRouteDataType_V1TopicsUnchanged(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dataType int32
		want     string
	}{
		{1000, TopicHeartbeat},
		{6001, TopicEvents},
		{8000, TopicBaseline},
		{5050, TopicAsset},
		{7000, TopicScanner},
		{3000, TopicEBPF},
		{9100, TopicRemediation},
		{9999, TopicCommandAck},
	}
	for _, tc := range cases {
		got := RouteDataType(tc.dataType, "")
		if got != tc.want {
			t.Fatalf("RouteDataType(%d): want %q, got %q", tc.dataType, tc.want, got)
		}
	}
}

func TestIsEngineCommand(t *testing.T) {
	t.Parallel()
	if !IsEngineCommand(11800) {
		t.Fatal("11800 should be engine command")
	}
	if !IsEngineCommand(11899) {
		t.Fatal("11899 should be engine command")
	}
	if IsEngineCommand(11799) {
		t.Fatal("11799 should NOT be engine command")
	}
	if IsEngineCommand(11900) {
		t.Fatal("11900 should NOT be engine command")
	}
}

func TestIsEngineAlert(t *testing.T) {
	t.Parallel()
	if !IsEngineAlert(11001) {
		t.Fatal("11001 should be engine alert")
	}
	if IsEngineAlert(10000) {
		t.Fatal("10000 should NOT be engine alert")
	}
}

func TestDLQTopic_V2(t *testing.T) {
	t.Parallel()
	if got := DLQTopic(TopicEngineCommand); got != "mxsec.engine.command.dlq" {
		t.Fatalf("DLQTopic: want mxsec.engine.command.dlq, got %s", got)
	}
}
