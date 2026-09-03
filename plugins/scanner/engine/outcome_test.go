package engine

import "testing"

func rep(name string, o EngineOutcome, threats int) EngineReport {
	return EngineReport{Engine: name, Outcome: o, Threats: threats}
}

// TestSummarize_NoEngineNeverReportsClean 一个引擎都没跑成时绝不能报 clean。
//
// 这是整个改动的理由：引擎不可用时原实现返回 (nil, nil)，调用方读到
// "零威胁、无错误"，任务上报 completed / threat_count=0。一台根本没装
// ClamAV 的主机，平台报告它没有恶意文件。没扫是覆盖缺口，不是结论。
func TestSummarize_NoEngineNeverReportsClean(t *testing.T) {
	out := Summarize([]EngineReport{
		rep("clamav", OutcomeUnavailable, 0),
		rep("yara", OutcomeUnavailable, 0),
	}, nil)
	if out.Status == "clean" {
		t.Fatal("没有任何引擎执行扫描时不得报告 clean")
	}
	if out.Status != "unavailable" {
		t.Errorf("status = %q, want unavailable", out.Status)
	}
}

// TestSummarize_PartialCoverageIsNotClean 只跑成一部分引擎且没发现威胁，
// 覆盖不全，不足以下"干净"的结论。
func TestSummarize_PartialCoverageIsNotClean(t *testing.T) {
	for _, degraded := range []EngineOutcome{OutcomeUnavailable, OutcomeFailed} {
		out := Summarize([]EngineReport{
			rep("clamav", OutcomeScanned, 0),
			rep("yara", degraded, 0),
		}, nil)
		if out.Status != "partial" {
			t.Errorf("一个引擎 %s 时 status = %q, want partial", degraded, out.Status)
		}
	}
}

// TestSummarize_ThreatsAlwaysInfected 发现威胁即 infected，
// 即便另一个引擎没跑成——已确认的威胁不因覆盖不全而降级。
func TestSummarize_ThreatsAlwaysInfected(t *testing.T) {
	threats := []ScanResult{{FilePath: "/tmp/eicar", ThreatName: "Eicar-Test-Signature"}}
	out := Summarize([]EngineReport{
		rep("clamav", OutcomeScanned, 1),
		rep("yara", OutcomeUnavailable, 0),
	}, threats)
	if out.Status != "infected" {
		t.Errorf("status = %q, want infected", out.Status)
	}
}

// TestSummarize_FullCoverageNoThreatIsClean 全部引擎跑成且无威胁才是 clean。
// 这条保证收紧后正常情况仍能给出确定结论，而不是一律 partial。
func TestSummarize_FullCoverageNoThreatIsClean(t *testing.T) {
	out := Summarize([]EngineReport{
		rep("clamav", OutcomeScanned, 0),
		rep("yara", OutcomeScanned, 0),
	}, nil)
	if out.Status != "clean" {
		t.Errorf("status = %q, want clean", out.Status)
	}
}

// TestSummarize_ReportsArePreserved 回执必须原样带出，
// 否则运维只看到 partial 却不知道是哪个引擎缺了。
func TestSummarize_ReportsArePreserved(t *testing.T) {
	reports := []EngineReport{
		rep("clamav", OutcomeScanned, 0),
		{Engine: "yara", Outcome: OutcomeFailed, Reason: "规则编译失败"},
	}
	out := Summarize(reports, nil)
	if len(out.Reports) != 2 {
		t.Fatalf("回执数 = %d, want 2", len(out.Reports))
	}
	if out.Reports[1].Reason != "规则编译失败" {
		t.Error("失败原因未保留，运维无从判断缺了什么")
	}
}
