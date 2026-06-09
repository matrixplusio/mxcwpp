package anomaly

import (
	"math/rand/v2"
	"testing"
)

func TestIForestUntrained(t *testing.T) {
	f := NewIForest()
	if f.Trained() {
		t.Fatal("expected untrained")
	}
	score := f.Score(make([]float64, featureCount))
	if score != -1 {
		t.Fatalf("expected -1 for untrained, got %f", score)
	}
}

func TestIForestTooFewSamples(t *testing.T) {
	f := NewIForest()
	data := make([][]float64, 10) // less than 32
	for i := range data {
		data[i] = make([]float64, featureCount)
	}
	f.Train(data)
	if f.Trained() {
		t.Fatal("expected untrained with too few samples")
	}
}

func TestIForestNormalVsAnomaly(t *testing.T) {
	f := NewIForest()

	// Generate 200 normal samples (clustered around origin).
	data := make([][]float64, 200)
	for i := range data {
		row := make([]float64, featureCount)
		for j := range row {
			row[j] = rand.NormFloat64() * 2 // std=2
		}
		data[i] = row
	}
	f.Train(data)

	if !f.Trained() {
		t.Fatal("expected trained")
	}

	// Normal sample should have lower anomaly score.
	normal := make([]float64, featureCount)
	for j := range normal {
		normal[j] = rand.NormFloat64() * 2
	}
	normalScore := f.Score(normal)

	// Anomalous sample: far from cluster.
	anomaly := make([]float64, featureCount)
	for j := range anomaly {
		anomaly[j] = 50 + rand.NormFloat64()
	}
	anomalyScore := f.Score(anomaly)

	t.Logf("normal score: %.4f, anomaly score: %.4f", normalScore, anomalyScore)

	if anomalyScore <= normalScore {
		t.Errorf("expected anomaly score > normal score: anomaly=%.4f normal=%.4f", anomalyScore, normalScore)
	}
}

func TestAvgPathLength(t *testing.T) {
	// c(1) = 0
	if c := avgPathLength(1); c != 0 {
		t.Errorf("c(1) = %f, want 0", c)
	}
	// c(256) = 2*H(255) - 2*255/256 ≈ 10.24
	c256 := avgPathLength(256)
	if c256 < 10.0 || c256 > 10.5 {
		t.Errorf("c(256) = %f, expected ~10.24", c256)
	}
}
