package server

import (
	"net"
	"testing"
	"time"
)

// TestTrackingListener_CloseConnByRemote 按对端地址关闭底层连接，客户端随即读到 EOF——
// 排空靠这个让 agent 重新拨号，而不是在同一条连接上重建 stream。
func TestTrackingListener_CloseConnByRemote(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewTrackingListener(base)
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	srv := <-accepted

	if l.Count() != 1 {
		t.Fatalf("应登记 1 条连接，实际 %d", l.Count())
	}
	if !l.CloseConn(srv.RemoteAddr().String()) {
		t.Fatal("按对端地址应能找到连接")
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("服务端关闭后客户端应读到错误")
	}
	if l.Count() != 0 {
		t.Fatalf("关闭后应注销，实际剩 %d", l.Count())
	}
	if l.CloseConn(srv.RemoteAddr().String()) {
		t.Fatal("已关闭的连接不应再找到")
	}
}

// TestTrackingListener_CloseAll 关闭全部连接后计数归零。
func TestTrackingListener_CloseAll(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewTrackingListener(base)
	defer l.Close()
	go func() {
		for {
			if _, err := l.Accept(); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for l.Count() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := l.CloseAll(); n != 3 || l.Count() != 0 {
		t.Fatalf("应关闭 3 条并归零，关闭 %d，剩 %d", n, l.Count())
	}
}
