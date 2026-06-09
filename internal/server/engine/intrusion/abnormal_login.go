package intrusion

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// AbnormalLoginDetector 检测异常登录:
//   - 地理位置异常: 与历史登录国家/地区差异大
//   - 时间异常: 凌晨 0-5 点登录
//   - IP 异常: 从未见过的 IP 段
//   - 用户异常: 历史登录用户外的新用户
//
// 实现 (简化):
//   - 每个 host 维护过去 30 天登录画像 (国家/小时/IP 段/用户 set)
//   - Successful login 与画像比对,新维度命中即 Alert
type AbnormalLoginDetector struct {
	mu       sync.Mutex
	profiles map[string]*loginProfile // host_id -> profile
}

type loginProfile struct {
	Countries   map[string]int       // country -> 命中次数
	HourBuckets map[int]int          // 0-23 -> 命中次数
	UsersSeen   map[string]time.Time // username -> last seen
	IPv4Net24   map[string]time.Time // /24 网段 -> last seen
	UpdatedAt   time.Time
}

// NewAbnormalLoginDetector 构造。
func NewAbnormalLoginDetector() *AbnormalLoginDetector {
	return &AbnormalLoginDetector{
		profiles: make(map[string]*loginProfile),
	}
}

// SuccessfulLogin 是单次成功登录事件 (Agent 上报)。
type SuccessfulLogin struct {
	HostID    string
	Username  string
	SourceIP  string
	Country   string // GeoIP 查询结果 (空时只查时间/IP/用户维度)
	Timestamp time.Time
}

// Ingest 处理一次成功登录。返回命中的异常维度列表 + Alert payload。
func (d *AbnormalLoginDetector) Ingest(_ context.Context, login SuccessfulLogin) (alertPayload []byte, hit bool) {
	if login.HostID == "" {
		return nil, false
	}
	now := login.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.profiles[login.HostID]
	if p == nil {
		p = newProfile()
		d.profiles[login.HostID] = p
	}

	var anomalies []string

	// 1. 地理位置: 国家不在历史画像
	if login.Country != "" {
		if _, ok := p.Countries[login.Country]; !ok {
			anomalies = append(anomalies, "new_country:"+login.Country)
		}
		p.Countries[login.Country]++
	}

	// 2. 时间: 凌晨 0-5 点登录 或 与历史画像差异大的小时
	hour := now.Hour()
	if hour >= 0 && hour <= 5 {
		// 凌晨直接告警 (除非该 host 经常凌晨被使用)
		if p.HourBuckets[hour] < 3 {
			anomalies = append(anomalies, "abnormal_hour:0-5am")
		}
	}
	p.HourBuckets[hour]++

	// 3. IP /24 网段
	if login.SourceIP != "" {
		net24 := ipToNet24(login.SourceIP)
		if _, ok := p.IPv4Net24[net24]; !ok {
			anomalies = append(anomalies, "new_ip_net:"+net24)
		}
		p.IPv4Net24[net24] = now
	}

	// 4. 用户: 全新用户
	if login.Username != "" {
		if _, ok := p.UsersSeen[login.Username]; !ok {
			// 90 天内未见过的用户视为异常
			anomalies = append(anomalies, "new_user:"+login.Username)
		}
		p.UsersSeen[login.Username] = now
	}

	p.UpdatedAt = now

	if len(anomalies) == 0 {
		return nil, false
	}

	payload, _ := json.Marshal(map[string]any{
		"host_id":   login.HostID,
		"username":  login.Username,
		"source_ip": login.SourceIP,
		"country":   login.Country,
		"timestamp": now,
		"anomalies": anomalies,
		"would_action": map[string]any{
			"type":   "alert_only",
			"reason": "异常登录维度命中: " + joinComma(anomalies),
		},
	})
	return payload, true
}

func newProfile() *loginProfile {
	return &loginProfile{
		Countries:   make(map[string]int),
		HourBuckets: make(map[int]int),
		UsersSeen:   make(map[string]time.Time),
		IPv4Net24:   make(map[string]time.Time),
	}
}

// ipToNet24 把 "1.2.3.4" 转 "1.2.3.0/24"。
func ipToNet24(ip string) string {
	last := len(ip) - 1
	for i := last; i >= 0; i-- {
		if ip[i] == '.' {
			return ip[:i] + ".0/24"
		}
	}
	return ip + "/24"
}

func joinComma(arr []string) string {
	if len(arr) == 0 {
		return ""
	}
	out := arr[0]
	for _, s := range arr[1:] {
		out += "," + s
	}
	return out
}
