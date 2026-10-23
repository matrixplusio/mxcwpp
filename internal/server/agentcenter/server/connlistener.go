package server

import (
	"net"
	"sync"
)

// TrackingListener 记下每条已接受的 TCP 连接，按对端地址可单独关闭。
//
// 滚动升级要把 agent 从本实例挪走，只结束 gRPC stream 不够：agent 的 ClientConn
// 仍是 Ready，会在同一条 HTTP/2 连接上重新建流，又回到本实例。必须关掉底层 TCP，
// agent 才会重新拨号，经前置的四层转发落到另一台。grpc-go 不提供按连接关闭的接口，
// 只能在监听器这一层拿住连接。
type TrackingListener struct {
	net.Listener
	mu    sync.Mutex
	conns map[string]net.Conn
}

// NewTrackingListener 包装监听器。
func NewTrackingListener(l net.Listener) *TrackingListener {
	return &TrackingListener{Listener: l, conns: make(map[string]net.Conn)}
}

// Accept 接受连接并登记。
func (l *TrackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, key: c.RemoteAddr().String(), l: l}
	l.mu.Lock()
	l.conns[tc.key] = tc
	l.mu.Unlock()
	return tc, nil
}

// CloseConn 关闭对端地址为 remote 的连接，找不到返回 false。
func (l *TrackingListener) CloseConn(remote string) bool {
	l.mu.Lock()
	c, ok := l.conns[remote]
	l.mu.Unlock()
	if !ok {
		return false
	}
	_ = c.Close()
	return true
}

// CloseAll 关闭全部已登记的连接，返回关闭数。
func (l *TrackingListener) CloseAll() int {
	l.mu.Lock()
	conns := make([]net.Conn, 0, len(l.conns))
	for _, c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return len(conns)
}

// Count 当前登记的连接数。
func (l *TrackingListener) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

type trackedConn struct {
	net.Conn
	key  string
	l    *TrackingListener
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		if c.l.conns[c.key] == c {
			delete(c.l.conns, c.key)
		}
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}
