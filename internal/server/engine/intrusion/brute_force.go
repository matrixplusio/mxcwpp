// Package intrusion 实现入侵检测六件套:
//   - 暴力破解 (brute_force.go)
//   - 异常登录 (abnormal_login.go)
//   - 反弹 shell (reverse_shell.go,等 PR)
//   - Web 后门 (web_shell.go)
//   - 本地提权 (privilege_escalation.go,等 PR)
//   - Rootkit/后门 (rootkit.go,等 PR)
//
// 详见 docs/edr-agent-design.md / docs/engine-detection-design.md
package intrusion

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// BruteForceWindow 是滑动窗口长度。
const BruteForceWindow = 5 * time.Minute

// BruteForceThreshold 是窗口内失败次数阈值。
const BruteForceThreshold = 5

// LoginAttempt 是单次登录尝试事件 (Agent 上报)。
type LoginAttempt struct {
	HostID    string
	Service   string // sshd / vsftpd / winrm / postfix
	SourceIP  string
	Username  string
	Success   bool
	Timestamp time.Time
}

// BruteForceDetector 滑动窗口检测暴力破解。
//
// 每个 (host_id, source_ip) pair 维护一个独立的滑动窗口。
// 失败计数超阈值时产 Alert + IP 入封禁建议清单。
type BruteForceDetector struct {
	window    time.Duration
	threshold int

	mu       sync.Mutex
	attempts map[string][]time.Time // key=host_id|source_ip -> 失败时间序列
}

// NewBruteForceDetector 构造检测器。
func NewBruteForceDetector(window time.Duration, threshold int) *BruteForceDetector {
	if window <= 0 {
		window = BruteForceWindow
	}
	if threshold <= 0 {
		threshold = BruteForceThreshold
	}
	return &BruteForceDetector{
		window:    window,
		threshold: threshold,
		attempts:  make(map[string][]time.Time),
	}
}

// Ingest 投喂一次登录尝试。命中阈值时返回 Alert payload。
func (d *BruteForceDetector) Ingest(_ context.Context, att LoginAttempt) (alertPayload []byte, hit bool) {
	if att.Success {
		// 成功登录: 清除该 IP 的失败记录 (合法用户重试成功)
		d.clearKey(d.key(att))
		return nil, false
	}

	now := att.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.key(att)

	// 清掉窗口外的旧记录
	deadline := now.Add(-d.window)
	old := d.attempts[key]
	fresh := old[:0]
	for _, t := range old {
		if t.After(deadline) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, now)
	d.attempts[key] = fresh

	if len(fresh) < d.threshold {
		return nil, false
	}

	// 命中阈值 → 产 Alert
	payload, _ := json.Marshal(map[string]any{
		"host_id":    att.HostID,
		"service":    att.Service,
		"source_ip":  att.SourceIP,
		"username":   att.Username,
		"fail_count": len(fresh),
		"window_sec": int(d.window.Seconds()),
		"first_at":   fresh[0],
		"last_at":    fresh[len(fresh)-1],
		"would_action": map[string]any{
			"type":         "ip_block",
			"target":       att.SourceIP,
			"duration_sec": 3600,
			"reason":       fmt.Sprintf("%d 次 %s 登录失败 (窗口 %ds)", len(fresh), att.Service, int(d.window.Seconds())),
		},
	})
	// 清除已告警的 key 避免重复触发 (后续若仍失败,需重新累积)
	delete(d.attempts, key)
	return payload, true
}

func (d *BruteForceDetector) key(att LoginAttempt) string {
	return att.HostID + "|" + att.SourceIP + "|" + att.Service
}

func (d *BruteForceDetector) clearKey(k string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.attempts, k)
}

// ParseSSHFailedFromFields 从 ev.fields 提取一次 sshd 失败登录。
//
// 期望 fields 包含: source_ip / username / log_msg 或类似字段。
// 实际接入时由 Agent 端 sshd journal_watcher 上报结构化字段。
func ParseSSHFailedFromFields(hostID string, fields map[string]string) *LoginAttempt {
	if hostID == "" {
		return nil
	}
	logMsg := fields["log_msg"]
	if logMsg == "" {
		return nil
	}
	// sshd "Failed password for X from Y" 模式
	if !contains(logMsg, "Failed password") && !contains(logMsg, "authentication failure") {
		return nil
	}
	ts := time.Now()
	if v, ok := fields["timestamp"]; ok {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil {
			ts = time.Unix(epoch, 0)
		}
	}
	return &LoginAttempt{
		HostID:    hostID,
		Service:   "sshd",
		SourceIP:  fields["source_ip"],
		Username:  fields["username"],
		Success:   false,
		Timestamp: ts,
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
