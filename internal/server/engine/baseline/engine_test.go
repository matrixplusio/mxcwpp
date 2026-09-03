package baseline

import (
	"testing"
	"time"
)

func TestHostBaselineLearningPhase(t *testing.T) {
	bl := &HostBaseline{phase: PhaseLearning}

	// Feed minSamples snapshots with constant values.
	metrics := [MetricCount]float64{10, 5, 2.0, 20, 10, 1, 15, 8, 3, 0.3, 50, 20, 0.05}
	for i := 0; i < minSamples; i++ {
		bl.Update(metrics)
	}

	// Still learning because learningPeriod (7 days) hasn't elapsed.
	if bl.IsReady() {
		t.Error("baseline should not be ready: learningPeriod not elapsed")
	}
	if bl.phase != PhaseLearning {
		t.Errorf("phase should be learning, got %s", bl.phase)
	}

	// Force firstSeen to 8 days ago.
	bl.mu.Lock()
	bl.firstSeen = time.Now().Add(-8 * 24 * time.Hour)
	bl.mu.Unlock()

	// One more update should trigger phase transition.
	bl.Update(metrics)
	if !bl.IsReady() {
		t.Error("baseline should be ready after learningPeriod + minSamples")
	}
	if bl.phase != PhaseActive {
		t.Errorf("phase should be active, got %s", bl.phase)
	}
}

func TestEngineIngestAndColdStart(t *testing.T) {
	eng := NewEngine(nil, nil) // memory-only, no logger

	// Build up global baseline with 101 samples.
	baseMetrics := [MetricCount]float64{10, 5, 2.0, 20, 10, 1, 15, 8, 3, 0.3, 50, 20, 0.05}
	for i := 0; i < minSamples+1; i++ {
		eng.global.Update(baseMetrics)
	}
	// Force global to active phase.
	eng.global.mu.Lock()
	eng.global.firstSeen = time.Now().Add(-8 * 24 * time.Hour)
	eng.global.phase = PhaseActive
	eng.global.mu.Unlock()

	if !eng.global.IsReady() {
		t.Fatal("global baseline should be ready")
	}

	// New host ingests normal metrics — should not alert (within threshold).
	result := eng.Ingest("host-new", baseMetrics)
	if result != nil {
		t.Error("normal metrics should not trigger alert")
	}

	// New host ingests extremely anomalous metrics.
	anomalous := [MetricCount]float64{1000, 500, 200, 2000, 1000, 100, 1500, 800, 300, 0.99, 5000, 2000, 0.95}
	result = eng.Ingest("host-anomaly", anomalous)
	if result == nil {
		t.Fatal("anomalous metrics should trigger cold-start alert")
	}
	if !result.ColdStart {
		t.Error("result should be marked as cold-start")
	}
	if result.RiskScore <= 0 {
		t.Errorf("risk_score should be > 0, got %.1f", result.RiskScore)
	}
}

func TestEngineActiveBaseline(t *testing.T) {
	eng := NewEngine(nil, nil)

	// Train baseline for host-a with consistent metrics.
	metrics := [MetricCount]float64{10, 5, 2.0, 20, 10, 1, 15, 8, 3, 0.3, 50, 20, 0.05}

	// Feed first sample to initialize, then backdate firstSeen.
	eng.Ingest("host-a", metrics)
	bl := eng.getOrCreate("host-a")
	bl.mu.Lock()
	bl.firstSeen = time.Now().Add(-8 * 24 * time.Hour)
	bl.mu.Unlock()

	// Feed slightly varied data to build non-zero stddev.
	for i := 0; i < minSamples+10; i++ {
		varied := metrics
		varied[0] = metrics[0] + float64(i%5) // slight variation
		varied[3] = metrics[3] + float64(i%3)
		eng.Ingest("host-a", varied)
	}

	if !bl.IsReady() {
		t.Fatal("host-a baseline should be ready")
	}

	// Normal ingest should not alert.
	result := eng.Ingest("host-a", metrics)
	if result != nil {
		t.Error("normal metrics should not trigger alert for active baseline")
	}

	// Extreme deviation should alert.
	extreme := [MetricCount]float64{10000, 5000, 2000, 20000, 10000, 1000, 15000, 8000, 3000, 0.99, 50000, 20000, 0.95}
	result = eng.Ingest("host-a", extreme)
	if result == nil {
		t.Fatal("extreme metrics should trigger alert")
	}
	if result.ColdStart {
		t.Error("active baseline alert should not be cold-start")
	}
	if len(result.Deviations) == 0 {
		t.Error("should have deviations")
	}
}

func TestHostStatuses(t *testing.T) {
	eng := NewEngine(nil, nil)

	metrics := [MetricCount]float64{10, 5, 2.0, 20, 10, 1, 15, 8, 3, 0.3, 50, 20, 0.05}
	eng.Ingest("host-1", metrics)
	eng.Ingest("host-2", metrics)

	statuses := eng.HostStatuses()
	if len(statuses) != 2 {
		t.Errorf("expected 2 host statuses, got %d", len(statuses))
	}

	for _, s := range statuses {
		if s.Phase != PhaseLearning {
			t.Errorf("new host %s should be in learning phase, got %s", s.HostID, s.Phase)
		}
		if s.Samples != 1 {
			t.Errorf("host %s should have 1 sample, got %d", s.HostID, s.Samples)
		}
	}
}
