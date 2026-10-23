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

const (
	// bruteAlertedTTL 一个来源被判为爆破之后，多久内它登录成功都算「爆破后得手」。
	// 爆破告警发出后失败计数会清零重新累计，不另记一笔的话，紧接着的那次成功就对不上了。
	bruteAlertedTTL = time.Hour
	// bruteMaxKeys 同时跟踪的（主机、来源）上限。对外主机面对的来源数没有上限，表不能跟着长。
	bruteMaxKeys = 200000
	// brutePruneInterval 清理过期条目的最小间隔。
	brutePruneInterval = time.Minute
)

// 登录事件类型，与认证日志插件上报的 event_type 一致。
const (
	AuthEventLoginSuccess = "auth_login_success"
	AuthEventLoginFailed  = "auth_login_failed"
)

// LoginAttempt 是一次（或合并上报的若干次）登录尝试。
type LoginAttempt struct {
	HostID    string
	Service   string // sshd / vsftpd / winrm / postfix
	SourceIP  string
	Username  string
	Success   bool
	Timestamp time.Time
	// Count 这条记录代表的次数。主机侧会把同一来源的连续失败合并上报，不按次数算的话
	// 一分钟几百次的爆破在这里只算一次。
	Count int
}

type failRecord struct {
	at time.Time
	n  int
}

// BruteForceDetector 滑动窗口检测暴力破解，以及爆破之后的登录成功。
//
// 每个 (host_id, source_ip, service) 维护一个独立的滑动窗口。
type BruteForceDetector struct {
	window    time.Duration
	threshold int

	mu        sync.Mutex
	attempts  map[string][]failRecord // 失败记录
	alerted   map[string]time.Time    // 最近被判为爆破的来源 → 判定时间
	lastPrune time.Time
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
		attempts:  make(map[string][]failRecord),
		alerted:   make(map[string]time.Time),
	}
}

// BruteForceResult 一次投喂的结果。
type BruteForceResult struct {
	// BruteForce 失败次数达到阈值。
	BruteForce []byte
	// SuccessAfterFailures 这次成功登录之前，同一来源刚在这台主机上失败了很多次。
	SuccessAfterFailures []byte
}

// Ingest 投喂一次登录尝试。
func (d *BruteForceDetector) Ingest(_ context.Context, att LoginAttempt) BruteForceResult {
	// 一律按服务端收到的时间算，不用事件自带的时间：那是主机报上来的。
	// 用它的话，报一批时间在将来的失败就能让这些记录永远不过期、把表占满，别的主机再怎么
	// 被爆破也进不了表；主机时钟落后或事件是落盘后补发的，记录又会一进来就被当成过期清掉。
	// 代价是补发的一批事件会被当成同时发生，只会更容易报，不会漏。
	now := bruteClock(att)
	n := att.Count
	if n < 1 {
		n = 1
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
	key := d.key(att)

	// 清掉窗口外的旧记录
	deadline := now.Add(-d.window)
	fresh := d.attempts[key][:0]
	total := 0
	for _, r := range d.attempts[key] {
		if r.at.After(deadline) {
			fresh = append(fresh, r)
			total += r.n
		}
	}

	if att.Success {
		alertedAt, wasAlerted := d.alerted[key]
		recentlyAlerted := wasAlerted && now.Sub(alertedAt) < bruteAlertedTTL
		// 合法用户输错一两次再输对是常态，清零即可；失败多到够得上爆破才值得一提。
		delete(d.attempts, key)
		delete(d.alerted, key)
		if total < d.threshold && !recentlyAlerted {
			return BruteForceResult{}
		}
		payload, _ := json.Marshal(map[string]any{
			"host_id":         att.HostID,
			"service":         att.Service,
			"source_ip":       att.SourceIP,
			"username":        att.Username,
			"recent_failures": total,
			"window_sec":      int(d.window.Seconds()),
			"brute_alerted":   recentlyAlerted,
			"login_at":        now,
			"would_action": map[string]any{
				"type":   "alert_only",
				"reason": fmt.Sprintf("%s 在多次登录失败之后以 %s 登录成功", att.SourceIP, att.Username),
			},
		})
		return BruteForceResult{SuccessAfterFailures: payload}
	}

	if len(fresh) == 0 && len(d.attempts) >= bruteMaxKeys {
		// 表满时不再跟踪新的来源。宁可漏掉一部分低频来源，也不让内存随来源数无限增长。
		return BruteForceResult{}
	}
	fresh = append(fresh, failRecord{at: now, n: n})
	total += n
	d.attempts[key] = fresh

	if total < d.threshold {
		return BruteForceResult{}
	}

	payload, _ := json.Marshal(map[string]any{
		"host_id":    att.HostID,
		"service":    att.Service,
		"source_ip":  att.SourceIP,
		"username":   att.Username,
		"fail_count": total,
		"window_sec": int(d.window.Seconds()),
		"first_at":   fresh[0].at,
		"last_at":    now,
		"would_action": map[string]any{
			"type":         "ip_block",
			"target":       att.SourceIP,
			"duration_sec": 3600,
			"reason":       bruteReason(att, total, int(d.window.Seconds())),
		},
	})
	// 清除已告警的 key 避免重复触发 (后续若仍失败,需重新累积)
	delete(d.attempts, key)
	d.alerted[key] = now
	return BruteForceResult{BruteForce: payload}
}

func (d *BruteForceDetector) key(att LoginAttempt) string {
	return att.HostID + "|" + att.SourceIP + "|" + att.Service
}

// bruteReason 告警描述里的一句话说明。最后一次尝试可能没有账号名
// （被 sshd 按来源惩罚、在认证开始前就丢掉的连接）。
func bruteReason(att LoginAttempt, total, windowSec int) string {
	r := fmt.Sprintf("来源 %s 在 %d 秒内 %s 登录失败 %d 次", att.SourceIP, windowSec, att.Service, total)
	if att.Username != "" {
		r += "，最近尝试的账号是 " + att.Username
	}
	return r
}

// bruteClock 给一次登录尝试定时间。生产上就是服务端的当前时间；
// 测试里换成读事件自带的时间，才能在一瞬间走完几分钟的窗口。
var bruteClock = func(LoginAttempt) time.Time { return time.Now() }

// pruneLocked 清掉早已过期的条目。只来过一次就再没出现的来源，没有后续事件去触发它自己的清理。
func (d *BruteForceDetector) pruneLocked(now time.Time) {
	if now.Sub(d.lastPrune) < brutePruneInterval {
		return
	}
	d.lastPrune = now
	deadline := now.Add(-d.window)
	for k, recs := range d.attempts {
		if len(recs) == 0 || !recs[len(recs)-1].at.After(deadline) {
			delete(d.attempts, k)
		}
	}
	for k, at := range d.alerted {
		if now.Sub(at) >= bruteAlertedTTL {
			delete(d.alerted, k)
		}
	}
}

// ParseLoginAttempt 从认证事件的字段里取出一次登录尝试；不是登录事件时返回 nil。
//
// 只看主机侧已经解析好的 event_type，不再从日志原文里找关键字：
// sshd 把对方提交的用户名原样写进日志，按「原文里包含 Accepted」判断成功是可以被伪造的。
func ParseLoginAttempt(hostID string, fields map[string]string) *LoginAttempt {
	if hostID == "" {
		return nil
	}
	var success bool
	switch fields["event_type"] {
	case AuthEventLoginSuccess:
		success = true
	case AuthEventLoginFailed:
	default:
		return nil
	}
	if fields["source_ip"] == "" {
		return nil
	}
	att := &LoginAttempt{
		HostID:    hostID,
		Service:   fields["service"],
		SourceIP:  fields["source_ip"],
		Username:  fields["username"],
		Success:   success,
		Timestamp: time.Now(),
		Count:     1,
	}
	if att.Service == "" {
		att.Service = "sshd"
	}
	if epoch, err := strconv.ParseInt(fields["timestamp"], 10, 64); err == nil && epoch > 0 {
		att.Timestamp = time.Unix(epoch, 0)
	}
	if n, err := strconv.Atoi(fields["count"]); err == nil && n > 0 {
		att.Count = n
	}
	return att
}
