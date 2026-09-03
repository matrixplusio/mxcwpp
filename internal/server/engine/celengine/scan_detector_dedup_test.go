package celengine

import (
	"regexp"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupScanAlertDB 建带 result_id 唯一约束的 alerts 表。
//
// 约束不是可选的：OnConflict 靠它才会走 DoUpdates。没有它，upsert 静默退化成
// 逐行插入——正是这次要修的缺陷，测试却会通过。
func setupScanAlertDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Exec(`CREATE TABLE alerts (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		result_id TEXT UNIQUE,
		host_id TEXT, rule_id TEXT, policy_id TEXT,
		source TEXT, severity TEXT, risk_score REAL, category TEXT,
		title TEXT, description TEXT, actual TEXT, expected TEXT,
		fix_suggestion TEXT, status TEXT, mode TEXT,
		would_action TEXT, action TEXT, action_result TEXT,
		last_notified_at TIMESTAMP, resolved_at TIMESTAMP,
		resolved_by TEXT, resolve_reason TEXT,
		attck_tactic TEXT, attck_technique TEXT,
		hit_count INTEGER DEFAULT 1, notify_count INTEGER DEFAULT 0,
		first_seen_at TIMESTAMP, last_seen_at TIMESTAMP,
		created_at TIMESTAMP, updated_at TIMESTAMP
	)`).Error; err != nil {
		t.Fatalf("create alerts: %v", err)
	}
	return db
}

// upsertScanAlert 复刻 triggerScanAlert 的落库语句。
//
// 检测路径本身要 Redis 滑窗，这里只验证落库这一段——缺陷就在这一段。
func upsertScanAlert(t *testing.T, db *gorm.DB, hostID, remoteAddr, desc, sev string) {
	t.Helper()
	now := model.ToLocalTime(time.Now())
	a := model.Alert{
		ResultID:    scanAlertResultID(hostID, remoteAddr),
		HostID:      hostID,
		RuleID:      "scan-detector",
		Source:      model.AlertSourceDetection,
		Severity:    sev,
		Category:    "port_scan",
		Title:       "端口扫描检测 - 来自 " + remoteAddr,
		Description: desc,
		Status:      model.AlertStatusActive,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	err := db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "result_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"last_seen_at": now,
			"hit_count":    gorm.Expr("hit_count + 1"),
			"description":  a.Description,
			"severity":     a.Severity,
			"status": gorm.Expr("CASE WHEN status = ? THEN ? ELSE status END",
				model.AlertStatusResolved, model.AlertStatusActive),
		}),
	}).Create(&a).Error
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
}

// TestScanAlertResultIDIsStable 同一 host+源 IP 的键必须与时间无关。
//
// 旧实现是 scan-{host}-{addr}-{UnixNano}，每次调用都不同，于是每个冷却窗都新建一行。
// 面对一个持续的内网来源，几台主机就能累积出数千条同义告警。
func TestScanAlertResultIDIsStable(t *testing.T) {
	a := scanAlertResultID("host-1", "10.0.0.5")
	time.Sleep(2 * time.Millisecond)
	b := scanAlertResultID("host-1", "10.0.0.5")
	if a != b {
		t.Fatalf("同一 host+源 IP 的 result_id 随时间变化了：%q != %q", a, b)
	}
	// 直接查纳秒特征：UnixNano 是 19 位连续数字，主机名与 IP 都到不了这个长度。
	if regexp.MustCompile(`[0-9]{13,}`).MatchString(a) {
		t.Errorf("result_id 含长数字串，疑似仍拼了时间戳：%q", a)
	}
}

// TestScanAlertResultIDSeparatesSources 不同源 IP 是不同的事，不能合并计数。
func TestScanAlertResultIDSeparatesSources(t *testing.T) {
	if scanAlertResultID("host-1", "10.0.0.5") == scanAlertResultID("host-1", "10.0.0.6") {
		t.Error("两个不同扫描源共用了一个 result_id，会把两次攻击并成一条")
	}
	if scanAlertResultID("host-1", "10.0.0.5") == scanAlertResultID("host-2", "10.0.0.5") {
		t.Error("两台主机共用了一个 result_id")
	}
}

// TestRepeatedScanAccumulatesInsteadOfInserting 重复命中累加而非刷行。
func TestRepeatedScanAccumulatesInsteadOfInserting(t *testing.T) {
	db := setupScanAlertDB(t)
	for i := 0; i < 20; i++ {
		upsertScanAlert(t, db, "host-1", "10.0.0.5", "第一轮端口列表", "low")
	}

	var n int64
	db.Model(&model.Alert{}).Where("rule_id = ?", "scan-detector").Count(&n)
	if n != 1 {
		t.Fatalf("20 次重复命中产生了 %d 行告警，应为 1 行", n)
	}
	var got model.Alert
	db.First(&got, "result_id = ?", scanAlertResultID("host-1", "10.0.0.5"))
	if got.HitCount != 20 {
		t.Errorf("hit_count = %d，应为 20", got.HitCount)
	}
}

// TestScanAlertRefreshesPortList 端口列表每轮会变，详情必须跟着刷新。
//
// 不刷新的话，详情永远停在第一次命中的端口集合，研判时看到的是过期证据。
func TestScanAlertRefreshesPortList(t *testing.T) {
	db := setupScanAlertDB(t)
	upsertScanAlert(t, db, "host-1", "10.0.0.5", "端口 22, 80", "low")
	upsertScanAlert(t, db, "host-1", "10.0.0.5", "端口 22, 80, 443, 3306", "medium")

	var got model.Alert
	db.First(&got, "result_id = ?", scanAlertResultID("host-1", "10.0.0.5"))
	if got.Description != "端口 22, 80, 443, 3306" {
		t.Errorf("description 未刷新：%q", got.Description)
	}
	if got.Severity != "medium" {
		t.Errorf("severity 未随扫描强度升级：%q", got.Severity)
	}
}

// TestResolvedScanAlertReactivates 已 resolved 的告警重新命中要复活。
func TestResolvedScanAlertReactivates(t *testing.T) {
	db := setupScanAlertDB(t)
	upsertScanAlert(t, db, "host-1", "10.0.0.5", "端口 22", "low")
	db.Model(&model.Alert{}).Where("rule_id = ?", "scan-detector").
		Update("status", model.AlertStatusResolved)

	upsertScanAlert(t, db, "host-1", "10.0.0.5", "端口 22, 80", "low")

	var got model.Alert
	db.First(&got, "result_id = ?", scanAlertResultID("host-1", "10.0.0.5"))
	if got.Status != model.AlertStatusActive {
		t.Errorf("resolved 后重新命中未复活，status = %q", got.Status)
	}
}

// TestIgnoredScanAlertStaysIgnored ignored 是人工判定的永久静音，不能被复活。
//
// 内网扫描器这类已知噪声就是靠 ignored 压住的。复活它等于把降噪成果清零——
// 一个持续的来源一天可产生数千次命中。
func TestIgnoredScanAlertStaysIgnored(t *testing.T) {
	db := setupScanAlertDB(t)
	upsertScanAlert(t, db, "host-1", "10.0.0.5", "端口 22", "low")
	db.Model(&model.Alert{}).Where("rule_id = ?", "scan-detector").
		Update("status", model.AlertStatusIgnored)

	for i := 0; i < 5; i++ {
		upsertScanAlert(t, db, "host-1", "10.0.0.5", "端口 22, 80", "low")
	}

	var got model.Alert
	db.First(&got, "result_id = ?", scanAlertResultID("host-1", "10.0.0.5"))
	if got.Status != model.AlertStatusIgnored {
		t.Errorf("ignored 被重新命中复活了，status = %q——降噪失效", got.Status)
	}
	if got.HitCount != 6 {
		t.Errorf("hit_count = %d，应为 6（静音不代表停止计数）", got.HitCount)
	}
}

// TestInternalSourceHasHigherThreshold 内网源的阈值必须显著高于外网源。
//
// 两者的正常形态不同：服务网格节点在一分钟内连上后端十几个业务端口是常态。
// 集群节点访问网关的几十个业务端口会被判成扫描，累积出数千条告警。
func TestInternalSourceHasHigherThreshold(t *testing.T) {
	if scanPortThresholdInternal <= scanPortThreshold {
		t.Fatalf("内网阈值 %d 未高于外网阈值 %d——内网服务调用会继续被判成扫描",
			scanPortThresholdInternal, scanPortThreshold)
	}
	// 集群节点单轮可触及几十个业务端口，阈值必须高于该量级才有意义。
	if scanPortThresholdInternal <= 33 {
		t.Errorf("内网阈值 %d 仍会命中常见的正常服务调用（数十个端口）",
			scanPortThresholdInternal)
	}
}

// TestInternalSourceRecognition 内外网判定必须覆盖实际用到的网段。
func TestInternalSourceRecognition(t *testing.T) {
	for _, ip := range []string{"10.0.0.122", "172.16.0.1", "192.168.1.1", "127.0.0.1"} {
		if !isInternalSource(ip) {
			t.Errorf("%s 应判为内网源", ip)
		}
	}
	// 持续侦察的来源通常是公网 VPS 地址，必须走外网阈值。
	// 这里用文档保留段代表：真实地址不进仓库（见 internal/deploy 的地址门禁）。
	for _, ip := range []string{"203.0.113.10", "198.51.100.20", "192.0.2.30"} {
		if isInternalSource(ip) {
			t.Errorf("%s 是公网地址，判成内网会让外网侦察漏检", ip)
		}
	}
}
