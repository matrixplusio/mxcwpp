package intrusion

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
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
//
// 画像是进程内内存起步，任何「首次见到」都算异常，因此冷启动时每台主机的
// 第一次正常登录都会同时命中新国家 + 新 IP 段 + 新用户。为此每台主机都有
// 一个学习期 (learning window): 期内照常更新画像，但不产告警。
// 学习期的退出条件见 graduated。
type AbnormalLoginDetector struct {
	mu       sync.Mutex
	profiles map[string]*loginProfile // host_id -> profile

	learnFor        time.Duration // 学习期时长 (自该主机首次登录起算)
	learnMinSamples int           // 学习期至少要观测到的登录次数

	suppressed uint64 // 学习期内被抑制的告警数 (可观测用,不做告警)

	db     *gorm.DB // 画像持久化后端; nil = 纯内存 (进程重启画像清零)
	logger *zap.Logger
}

type loginProfile struct {
	Countries   map[string]int       // country -> 命中次数
	HourBuckets map[int]int          // 0-23 -> 命中次数
	UsersSeen   map[string]time.Time // username -> last seen
	IPv4Net24   map[string]time.Time // /24 网段 -> last seen
	FirstSeen   time.Time            // 该主机首次登录时间 (学习期起点)
	Samples     int                  // 已观测的登录次数
	UpdatedAt   time.Time
	dirty       bool // 自上次 checkpoint 后有变更
}

const (
	// DefaultLearningWindow 是一台主机建立登录画像的默认学习期。
	// 取 7 天以覆盖「工作日 + 周末」两种登录形态，避免周一才出现的运维账号
	// 在周二被当成新用户告警。
	DefaultLearningWindow = 7 * 24 * time.Hour

	// DefaultLearningMinSamples 是退出学习期所需的最少登录样本数。
	// 只看时长不够: 一台一周只登录一次的主机，画像里只有一个 IP 段和一个用户，
	// 出了学习期第二次登录仍会误报。
	DefaultLearningMinSamples = 10

	// profileEntryTTL 是用户/IP 段在画像里的保留期。超期条目按「没见过」处理——
	// 代码注释一直说 90 天，此前从未真的过期。画像要落库，只增不减的 map 会把
	// 一行撑到无限大。
	profileEntryTTL = 90 * 24 * time.Hour

	// profileEntryCap 是单台主机画像里用户/IP 段各自的条目上限。
	// TTL 挡不住 90 天内扫过一万个 /24 的主机，这里按 last-seen 保留最新的。
	profileEntryCap = 1024
)

// NewAbnormalLoginDetector 用默认学习期构造。
func NewAbnormalLoginDetector() *AbnormalLoginDetector {
	return NewAbnormalLoginDetectorWithWindow(DefaultLearningWindow, DefaultLearningMinSamples)
}

// NewAbnormalLoginDetectorWithWindow 指定学习期构造。
// 非正的时长或样本数按默认值处理——学习期不允许被配置成零，
// 那等同于回到「冷启动即刷屏」。
func NewAbnormalLoginDetectorWithWindow(learnFor time.Duration, minSamples int) *AbnormalLoginDetector {
	if learnFor <= 0 {
		learnFor = DefaultLearningWindow
	}
	if minSamples <= 0 {
		minSamples = DefaultLearningMinSamples
	}
	return &AbnormalLoginDetector{
		profiles:        make(map[string]*loginProfile),
		learnFor:        learnFor,
		learnMinSamples: minSamples,
		logger:          zap.NewNop(),
	}
}

// NewAbnormalLoginDetectorWithStore 用默认学习期构造，并把画像持久化到 db。
// 构造后必须调 LoadFromDB 恢复画像、StartCheckpoint 起周期落盘，两者缺一
// 等于没持久化。db 为 nil 时退化成纯内存检测器。
func NewAbnormalLoginDetectorWithStore(db *gorm.DB, logger *zap.Logger) *AbnormalLoginDetector {
	d := NewAbnormalLoginDetector()
	d.db = db
	if logger != nil {
		d.logger = logger
	}
	return d
}

// graduated 判断该主机是否已走完学习期。
// 时长与样本数**都**满足才算——两个条件各自堵一种误报:
// 时长堵「刚接线就刷屏」，样本数堵「低频主机画像太稀疏」。
//
// 代价是登录极少的主机可能长期留在学习期，检测对它一直不生效。
// 这是有意选的方向: 漏一条 medium 告警，好过让人不再看这个告警源。
func (p *loginProfile) graduated(now time.Time, learnFor time.Duration, minSamples int) bool {
	return p.Samples >= minSamples && now.Sub(p.FirstSeen) >= learnFor
}

// LearningStats 是学习期的可观测快照。
type LearningStats struct {
	HostsLearning   int    // 仍在学习期的主机数
	HostsGraduated  int    // 已走完学习期的主机数
	SuppressedTotal uint64 // 学习期内被抑制的告警累计数
}

// Stats 返回学习期快照。接线后应把它导出为指标——学习期是「静默不告警」，
// 没有指标就分不清「一切正常」和「检测根本没生效」。
func (d *AbnormalLoginDetector) Stats() LearningStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := LearningStats{SuppressedTotal: d.suppressed}
	for _, p := range d.profiles {
		if p.graduated(p.UpdatedAt, d.learnFor, d.learnMinSamples) {
			st.HostsGraduated++
		} else {
			st.HostsLearning++
		}
	}
	return st
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
		p = newProfile(now)
		d.profiles[login.HostID] = p
	}
	p.Samples++

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
	p.dirty = true
	p.prune(now)

	if len(anomalies) == 0 {
		return nil, false
	}

	// 学习期内画像照常更新（上面已经更新完），但不产告警。
	// 冷启动时每台主机的第一次登录必然命中新国家 + 新 IP 段 + 新用户三条，
	// 那不是入侵信号，只是画像还是空的。
	if !p.graduated(now, d.learnFor, d.learnMinSamples) {
		d.suppressed++
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

// prune 丢弃超期或超量的用户/IP 段条目。
// 在 Ingest 里做而不是在落库时做: 内存与库里必须是同一份画像，否则同一台主机
// 重启前后对同一个用户会给出不同结论。
func (p *loginProfile) prune(now time.Time) {
	pruneSeen(p.UsersSeen, now)
	pruneSeen(p.IPv4Net24, now)
}

// pruneSeen 先按 TTL 删，仍超上限则按 last-seen 从旧到新删到上限。
func pruneSeen(seen map[string]time.Time, now time.Time) {
	if len(seen) <= profileEntryCap {
		// 未超上限时只做 TTL 清理，且规模小，逐条扫描的代价可以忽略。
		for k, last := range seen {
			if now.Sub(last) > profileEntryTTL {
				delete(seen, k)
			}
		}
		return
	}
	keys := make([]string, 0, len(seen))
	for k, last := range seen {
		if now.Sub(last) > profileEntryTTL {
			delete(seen, k)
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) <= profileEntryCap {
		return
	}
	sort.Slice(keys, func(i, j int) bool { return seen[keys[i]].Before(seen[keys[j]]) })
	for _, k := range keys[:len(keys)-profileEntryCap] {
		delete(seen, k)
	}
}

func newProfile(firstSeen time.Time) *loginProfile {
	return &loginProfile{
		Countries:   make(map[string]int),
		HourBuckets: make(map[int]int),
		UsersSeen:   make(map[string]time.Time),
		IPv4Net24:   make(map[string]time.Time),
		FirstSeen:   firstSeen,
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
