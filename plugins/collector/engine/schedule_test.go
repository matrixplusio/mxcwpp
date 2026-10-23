package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

type probeHandler struct {
	name    string
	order   *[]string
	mu      *sync.Mutex
	running *int32
	maxSeen *int32
}

func (p probeHandler) Collect(context.Context) ([]interface{}, error) {
	n := atomic.AddInt32(p.running, 1)
	for {
		m := atomic.LoadInt32(p.maxSeen)
		if n <= m || atomic.CompareAndSwapInt32(p.maxSeen, m, n) {
			break
		}
	}
	time.Sleep(5 * time.Millisecond)
	p.mu.Lock()
	*p.order = append(*p.order, p.name)
	p.mu.Unlock()
	atomic.AddInt32(p.running, -1)
	return []interface{}{struct{}{}}, nil
}

// 首轮按优先级逐个执行，任意时刻只有一个采集器在跑。
func TestFirstRoundRunsByPriorityOneAtATime(t *testing.T) {
	e := NewEngine(nil, zap.NewNop())
	e.report = func(*HandlerConfig, []interface{}) error { return nil }

	var order []string
	var mu sync.Mutex
	var running, maxSeen int32
	reg := func(name string, prio int) {
		e.RegisterHandler(name, prio, time.Hour, probeHandler{name, &order, &mu, &running, &maxSeen})
	}
	reg("jar_scanner", 4)
	reg("software", 3)
	reg("process", 1)
	reg("user", 2)
	reg("port", 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(order)
		mu.Unlock()
		if n == 5 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("首轮未在时限内完成: %v", order)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	want := []string{"port", "process", "user", "software", "jar_scanner"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("首轮顺序应为 %v，实际 %v", want, order)
		}
	}
	if maxSeen != 1 {
		t.Fatalf("同一时刻最多只能有一个采集器在跑，实际出现 %d 个并行", maxSeen)
	}
}
