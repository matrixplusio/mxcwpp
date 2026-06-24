package plugins

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
	"google.golang.org/protobuf/proto"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
)

// newTestClient 构造一对内存 pipe 的 Client，避开 fd 3/4
func newTestClient(t *testing.T) (*Client, io.WriteCloser, io.ReadCloser) {
	t.Helper()
	rxR, rxW := io.Pipe() // agent -> plugin: agent 写 rxW, plugin 读 rxR
	txR, txW := io.Pipe() // plugin -> agent: plugin 写 txW, agent 读 txR
	c := &Client{
		rx:     rxR,
		tx:     txW,
		reader: bufio.NewReader(rxR),
		writer: bufio.NewWriter(txW),
		rmu:    &sync.Mutex{},
		wmu:    &sync.Mutex{},
	}
	return c, rxW, txR
}

// writeTask 模拟 agent 向 plugin 投递一条 Task
func writeTask(t *testing.T, w io.Writer, dataType int32, token string) {
	t.Helper()
	task := &bridge.Task{DataType: dataType, Token: token}
	buf, err := proto.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(buf))); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(buf); err != nil {
		t.Fatal(err)
	}
}

// drainPongs 模拟 agent 端读 plugin 写入的 Record，统计 pong 数量
func drainPongs(t *testing.T, r io.Reader, pongCount *atomic.Int32, stop <-chan struct{}) {
	t.Helper()
	go func() {
		br := bufio.NewReader(r)
		for {
			select {
			case <-stop:
				return
			default:
			}
			var size uint32
			if err := binary.Read(br, binary.LittleEndian, &size); err != nil {
				return
			}
			buf := make([]byte, size)
			if _, err := io.ReadFull(br, buf); err != nil {
				return
			}
			rec := &bridge.Record{}
			if err := proto.Unmarshal(buf, rec); err != nil {
				continue
			}
			if rec.DataType == 9001 {
				pongCount.Add(1)
			}
		}
	}()
}

// TestReceiveTaskLoopForwardsTask 基本流程：单条 Task 推到 taskCh
func TestReceiveTaskLoopForwardsTask(t *testing.T) {
	client, rxW, txR := newTestClient(t)
	defer rxW.Close()
	defer txR.Close()

	logger := zaptest.NewLogger(t)
	taskCh := make(chan *bridge.Task, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		ReceiveTaskLoop(ctx, client, taskCh, logger)
		close(done)
	}()

	writeTask(t, rxW, 9101, "tok-1")

	select {
	case task := <-taskCh:
		if task.Token != "tok-1" || task.DataType != 9101 {
			t.Errorf("unexpected task: %+v", task)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for task")
	}
}

// TestReceiveTaskLoopAutoPong 验证 ping 不返回业务，并自动回 pong
func TestReceiveTaskLoopAutoPong(t *testing.T) {
	client, rxW, txR := newTestClient(t)
	defer rxW.Close()
	defer txR.Close()

	logger := zaptest.NewLogger(t)
	taskCh := make(chan *bridge.Task, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var pongs atomic.Int32
	stop := make(chan struct{})
	defer close(stop)
	drainPongs(t, txR, &pongs, stop)

	go ReceiveTaskLoop(ctx, client, taskCh, logger)

	// 投 1 条 ping (DataType=9000) + 1 条业务任务
	writeTask(t, rxW, 9000, "ping-1")
	writeTask(t, rxW, 9101, "biz-1")

	// 业务任务必须到 taskCh，ping 不应到
	select {
	case task := <-taskCh:
		if task.Token != "biz-1" {
			t.Errorf("ping leaked through as token=%q", task.Token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// 等 pong 写出
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pongs.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pongs.Load() < 1 {
		t.Errorf("expected pong, got %d", pongs.Load())
	}
}

// TestReceiveTaskLoopNeverBlocksOnFullTaskCh
// 核心回归测试：业务 taskCh 满时 ReceiveTaskLoop 不能阻塞。
// 验证：投 N 条业务 + 间插 ping，taskCh cap=1 业务不消费，ping 仍应被自动回复。
func TestReceiveTaskLoopNeverBlocksOnFullTaskCh(t *testing.T) {
	client, rxW, txR := newTestClient(t)
	defer rxW.Close()
	defer txR.Close()

	logger := zaptest.NewLogger(t)
	// 故意小 cap 模拟业务阻塞
	taskCh := make(chan *bridge.Task, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var pongs atomic.Int32
	stop := make(chan struct{})
	defer close(stop)
	drainPongs(t, txR, &pongs, stop)

	go ReceiveTaskLoop(ctx, client, taskCh, logger)

	// 故意不消费 taskCh，模拟业务卡住
	// 投 5 条业务（应触发 deferred 投递）
	for range 5 {
		writeTask(t, rxW, 9101, "biz")
	}
	// 间插投 3 条 ping
	for range 3 {
		writeTask(t, rxW, 9000, "ping")
	}

	// 等 pong：业务卡住时 ping 仍需被自动回复
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pongs.Load() >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pongs.Load() < 3 {
		t.Fatalf("expected >=3 pongs (ping must not be blocked by taskCh full), got %d", pongs.Load())
	}
}

// TestReceiveTaskLoopExitOnPipeClose 验证 EOF 时优雅退出
func TestReceiveTaskLoopExitOnPipeClose(t *testing.T) {
	client, rxW, txR := newTestClient(t)
	defer txR.Close()

	logger := zaptest.NewLogger(t)
	taskCh := make(chan *bridge.Task, 4)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		ReceiveTaskLoop(ctx, client, taskCh, logger)
		close(done)
	}()

	rxW.Close() // 关 pipe，触发 EOF

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReceiveTaskLoop did not exit on EOF")
	}
}
