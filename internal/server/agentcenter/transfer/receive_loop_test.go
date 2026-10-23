package transfer

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
)

// silentStream 模拟发送侧停摆的 Agent：连接还在，但 Recv 一直收不到东西，
// 直到流的上下文被取消（gRPC 在 handler 返回后就是这么做的）。
type silentStream struct {
	ctx      context.Context
	returned chan struct{}
}

func (s *silentStream) Recv() (*grpcProto.PackagedData, error) {
	<-s.ctx.Done()
	close(s.returned)
	return nil, s.ctx.Err()
}

// pacedStream 每隔 every 发一个包，发完 n 个后返回 EOF。
type pacedStream struct {
	every time.Duration
	left  int
}

func (p *pacedStream) Recv() (*grpcProto.PackagedData, error) {
	if p.left == 0 {
		return nil, io.EOF
	}
	time.Sleep(p.every)
	p.left--
	return &grpcProto.PackagedData{AgentId: "a"}, nil
}

func newTestService() *Service {
	return &Service{logger: zap.NewNop()}
}

func TestStreamIdleTimeoutFor(t *testing.T) {
	cases := map[int]time.Duration{
		0:   3 * time.Minute,
		60:  3 * time.Minute,
		120: 6 * time.Minute,
	}
	for sec, want := range cases {
		if got := streamIdleTimeoutFor(sec); got != want {
			t.Errorf("heartbeat %ds: idle timeout = %s, want %s", sec, got, want)
		}
	}
	// 必须短于 5 分钟的离线判定，流才能在主机被判离线前重置
	if streamIdleTimeoutFor(60) >= 5*time.Minute {
		t.Error("default idle timeout must stay below the offline threshold")
	}
}

func TestReceiveLoopClosesSilentStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rx := &silentStream{ctx: ctx, returned: make(chan struct{})}
	var handled atomic.Int32

	done := make(chan error, 1)
	go func() {
		done <- newTestService().receiveLoop(ctx, rx, &Connection{AgentID: "a"}, 50*time.Millisecond,
			func(*grpcProto.PackagedData) { handled.Add(1) })
	}()

	select {
	case err := <-done:
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("want Unavailable so the agent reconnects, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("silent stream was never closed")
	}
	if handled.Load() != 0 {
		t.Fatalf("handled %d packets from a silent stream", handled.Load())
	}

	// handler 返回后 gRPC 取消流上下文，接收协程必须随之退出
	cancel()
	select {
	case <-rx.returned:
	case <-time.After(2 * time.Second):
		t.Fatal("receive goroutine leaked after the stream was closed")
	}
}

func TestReceiveLoopKeepsActiveStream(t *testing.T) {
	// 总时长约 200ms，远超 80ms 的空闲阈值，但每个包间隔都在阈值内
	rx := &pacedStream{every: 20 * time.Millisecond, left: 10}
	var handled atomic.Int32

	err := newTestService().receiveLoop(context.Background(), rx, &Connection{AgentID: "a"}, 80*time.Millisecond,
		func(*grpcProto.PackagedData) { handled.Add(1) })
	if err != nil {
		t.Fatalf("active stream must end cleanly on EOF, got %v", err)
	}
	if handled.Load() != 10 {
		t.Fatalf("handled %d packets, want 10", handled.Load())
	}
}

func TestReceiveLoopEOF(t *testing.T) {
	rx := &pacedStream{left: 0}
	err := newTestService().receiveLoop(context.Background(), rx, &Connection{AgentID: "a"}, time.Second,
		func(*grpcProto.PackagedData) { t.Fatal("no packet expected") })
	if err != nil {
		t.Fatalf("EOF must end the stream without error, got %v", err)
	}
}
