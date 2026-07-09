package transport

import (
	"testing"
	"time"
)

func TestRandSpread(t *testing.T) {
	// max<=0 → 0（不延迟）
	if d := randSpread(0); d != 0 {
		t.Errorf("randSpread(0) = %v, want 0", d)
	}
	if d := randSpread(-time.Second); d != 0 {
		t.Errorf("randSpread(-1s) = %v, want 0", d)
	}

	// max>0 → 落在 [0, max)，多次采样验证边界
	const max = 100 * time.Millisecond
	for range 1000 {
		d := randSpread(max)
		if d < 0 || d >= max {
			t.Fatalf("randSpread(%v) = %v, out of [0,%v)", max, d, max)
		}
	}
}

func TestWithJitter(t *testing.T) {
	// ±30%：1s → [0.7s, 1.3s]
	const base = time.Second
	for range 1000 {
		d := withJitter(base)
		if d < 700*time.Millisecond || d > 1300*time.Millisecond {
			t.Fatalf("withJitter(1s) = %v, out of [0.7s,1.3s]", d)
		}
	}
	if d := withJitter(0); d != 0 {
		t.Errorf("withJitter(0) = %v, want 0", d)
	}
}
