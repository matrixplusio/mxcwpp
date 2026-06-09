package rollout

import "testing"

func TestHashBucketDistribution(t *testing.T) {
	const ruleID = "rule-1"
	buckets := make(map[int]int)
	N := 10000
	for i := 0; i < N; i++ {
		host := "host-" + itoa(i)
		buckets[hashBucket(ruleID, host)]++
	}
	if len(buckets) < 80 {
		t.Errorf("expected >80 distinct buckets in 100, got %d", len(buckets))
	}
}

func TestIsActiveForHost(t *testing.T) {
	r := &Resolver{cache: map[string]State{}}
	if !r.IsActiveForHost("t1", "r1", "h1") {
		t.Fatal("no rollout record should default active")
	}
	r.cache["t1|r1"] = State{Percent: 0}
	if r.IsActiveForHost("t1", "r1", "h1") {
		t.Fatal("percent=0 should be inactive")
	}
	r.cache["t1|r1"] = State{Percent: 100}
	if !r.IsActiveForHost("t1", "r1", "h1") {
		t.Fatal("percent=100 should be active")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
