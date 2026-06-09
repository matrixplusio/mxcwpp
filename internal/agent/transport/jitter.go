package transport

import (
	"math/rand"
	"time"
)

// withJitter P2-3 加 ±30% 随机抖动防雷鸣群.
//
// 1w 主机同时断连重连场景: 所有 Agent 指数退避到同步时间点冲击 AgentCenter.
// 加 0.7d ~ 1.3d 随机 jitter 分散重连时间点, 防 AC 被瞬时压垮.
func withJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	// 0.7 ~ 1.3 区间
	jitter := 0.7 + rand.Float64()*0.6
	return time.Duration(float64(d) * jitter)
}
