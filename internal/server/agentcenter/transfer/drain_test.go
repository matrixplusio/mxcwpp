package transfer

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newDrainService(n int) (*Service, *[]string, *sync.Mutex) {
	s := &Service{logger: zap.NewNop(), connections: map[string]*Connection{}}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("agent-%d", i)
		_, cancel := context.WithCancel(context.Background())
		s.connections[id] = &Connection{AgentID: id, remoteAddr: "10.0.0.1:" + fmt.Sprint(40000+i), cancel: cancel}
	}
	var mu sync.Mutex
	closed := []string{}
	s.SetConnTracker(func(remote string) bool {
		mu.Lock()
		closed = append(closed, remote)
		mu.Unlock()
		// 模拟 stream 退出后的注销
		s.connMu.Lock()
		for id, c := range s.connections {
			if c.remoteAddr == remote {
				delete(s.connections, id)
			}
		}
		s.connMu.Unlock()
		return true
	}, nil, nil)
	return s, &closed, &mu
}

// TestDrain_ClosesAllInBatches 分批关闭全部连接，期间就绪状态为排空。
func TestDrain_ClosesAllInBatches(t *testing.T) {
	s, closed, mu := newDrainService(7)
	n := s.Drain(context.Background(), 3, time.Millisecond)
	if n != 7 || len(*closed) != 7 {
		t.Fatalf("应关闭 7 条，返回 %d，实际关闭 %d", n, len(*closed))
	}
	mu.Lock()
	defer mu.Unlock()
	if !s.Draining() {
		t.Fatal("排空完成后仍应保持排空状态，直到显式 Undrain 或进程退出")
	}
}

// TestDrain_StopsOnUndrain Undrain 能中止排空，剩余连接保留。
func TestDrain_StopsOnUndrain(t *testing.T) {
	s, closed, mu := newDrainService(10)
	done := make(chan int)
	go func() { done <- s.Drain(context.Background(), 2, 50*time.Millisecond) }()
	time.Sleep(20 * time.Millisecond)
	s.Undrain()
	n := <-done
	mu.Lock()
	defer mu.Unlock()
	if n >= 10 || len(*closed) >= 10 {
		t.Fatalf("中止后不应关完全部连接，实际关闭 %d", len(*closed))
	}
}

// TestDrain_SkipsAlreadyClosed 关过但尚未注销的连接不重复关，也不让排空空转。
func TestDrain_SkipsAlreadyClosed(t *testing.T) {
	s := &Service{logger: zap.NewNop(), connections: map[string]*Connection{}}
	_, cancel := context.WithCancel(context.Background())
	s.connections["a"] = &Connection{AgentID: "a", remoteAddr: "x:1", cancel: cancel}
	calls := 0
	s.SetConnTracker(func(string) bool { calls++; return true }, nil, nil) // 不注销，模拟 stream 迟迟未退出
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	s.Drain(ctx, 5, time.Millisecond)
	if calls != 1 {
		t.Fatalf("同一连接只应关闭一次，实际 %d 次", calls)
	}
}

// TestDrain_ClosesUnregisteredAtEnd 已登记的断完后，建了流还没发首包的连接也一并关掉。
func TestDrain_ClosesUnregisteredAtEnd(t *testing.T) {
	s := &Service{logger: zap.NewNop(), connections: map[string]*Connection{}}
	allClosed := 0
	s.SetConnTracker(func(string) bool { return true }, func() int { return 3 }, func() int { allClosed++; return 3 })
	if n := s.Drain(context.Background(), 5, time.Millisecond); n != 3 || allClosed != 1 {
		t.Fatalf("应在收尾时关闭未登记连接一次，返回 %d，调用 %d 次", n, allClosed)
	}
}
