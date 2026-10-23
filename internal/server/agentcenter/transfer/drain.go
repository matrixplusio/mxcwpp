package transfer

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// 排空（drain）：滚动升级时把本实例上的 agent 分批挪到另一台 AC。
//
// 进入排空后：就绪检查返回失败，前置四层转发不再把新连接分过来；已有连接按批关闭
// 底层 TCP，agent 重新拨号后落到别的实例；断连不记离线、不发离线告警——这不是离线，
// 是换了一台。万一 agent 没能连上别处，另一台的心跳超时检测会在几分钟内照常判离线。
//
// 分批是为了不重演一次性全网重连：每批之间留出间隔，让对端逐批完成 TLS 握手与首包处理。

// SetConnTracker 注入监听器提供的能力：按对端地址关闭底层连接、当前 TCP 连接数、关闭全部连接。
func (s *Service) SetConnTracker(closer func(remote string) bool, count func() int, closeAll func() int) {
	s.connCloser = closer
	s.tcpCount = count
	s.closeAll = closeAll
}

// TCPConnections 本实例当前的 TCP 连接数，包括已建流、尚未发首包（未登记）的。
// 排空是否完成以它为准：只看已登记的连接数，会漏掉这些「在路上」的连接。
func (s *Service) TCPConnections() int {
	if s.tcpCount == nil {
		return s.GetOnlineAgentCount()
	}
	return s.tcpCount()
}

// rejectIfDraining 排空中则关掉这条连接的底层 TCP，返回 true。
func (s *Service) rejectIfDraining(remote string) bool {
	if !s.draining.Load() {
		return false
	}
	if s.connCloser != nil && remote != "" {
		s.connCloser(remote)
	}
	return true
}

// Draining 是否处于排空状态。
func (s *Service) Draining() bool { return s.draining.Load() }

// Undrain 退出排空（中止一次排空，或升级后恢复接流量前调用）。
func (s *Service) Undrain() {
	s.draining.Store(false)
	s.logger.Info("已退出排空，恢复接收新连接")
}

// Drain 进入排空并分批断开现有连接，阻塞到全部断开、ctx 取消或被 Undrain 中止。返回断开的连接数。
func (s *Service) Drain(ctx context.Context, batch int, interval time.Duration) int {
	if batch <= 0 {
		batch = 20
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	s.draining.Store(true)
	s.logger.Info("开始排空", zap.Int("batch", batch), zap.Duration("interval", interval),
		zap.Int("connections", s.GetOnlineAgentCount()))

	closed := 0
	// 已关过的连接在 stream 退出前仍留在连接表里，记下来避免重复关、也避免误判「还没排完」。
	done := make(map[*Connection]bool)
	for {
		if !s.draining.Load() {
			s.logger.Info("排空已中止", zap.Int("closed", closed))
			return closed
		}
		conns := s.snapshotConnections(batch, done)
		if len(conns) == 0 {
			// 已登记的都断完了，剩下的是建了流还没发首包的连接（最多等一个心跳周期才会登记），
			// 一并关掉，排空才能立刻收口，而不是等它们自己发首包时再被拦。
			if s.closeAll != nil {
				closed += s.closeAll()
			}
			s.logger.Info("排空完成", zap.Int("closed", closed))
			return closed
		}
		for _, c := range conns {
			s.closeConnection(c)
			done[c] = true
			closed++
		}
		select {
		case <-ctx.Done():
			s.logger.Warn("排空被取消", zap.Int("closed", closed), zap.Int("remaining", s.GetOnlineAgentCount()))
			return closed
		case <-time.After(interval):
		}
	}
}

func (s *Service) snapshotConnections(n int, skip map[*Connection]bool) []*Connection {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	out := make([]*Connection, 0, n)
	for _, c := range s.connections {
		if len(out) >= n {
			break
		}
		if skip[c] {
			continue
		}
		out = append(out, c)
	}
	return out
}

// closeConnection 关掉连接的底层 TCP；拿不到（无监听器注入或已关闭）时退回只结束 stream。
func (s *Service) closeConnection(c *Connection) {
	if s.connCloser != nil && c.remoteAddr != "" && s.connCloser(c.remoteAddr) {
		return
	}
	c.cancel()
}
