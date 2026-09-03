package kube

import (
	"encoding/json"
	"fmt"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// setupAlarmFilterTestDB 构建 SQLite 内存库并建表
// 手动 CREATE TABLE 以避免 MySQL 专有的 `ON UPDATE CURRENT_TIMESTAMP` 子句在 SQLite 报错
// 限制连接池为 1：SQLite `:memory:` 模式下每个连接独立，多连接会看不到表
func setupAlarmFilterTestDB(t *testing.T) (*gorm.DB, *KubeAlarmService) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec(`CREATE TABLE kube_alarms (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		cluster_id       INTEGER NOT NULL,
		cluster_name     TEXT,
		severity         TEXT,
		alarm_type       TEXT,
		rule_id          TEXT,
		title            TEXT,
		description      TEXT,
		remediation      TEXT,
		message          TEXT,
		namespace        TEXT,
		pod_name         TEXT,
		container_name   TEXT,
		container_id     TEXT,
		node_name        TEXT,
		image_name       TEXT,
		target           TEXT,
		fingerprint      TEXT,
		count            INTEGER NOT NULL DEFAULT 1,
		raw_data         TEXT,
		status           TEXT NOT NULL DEFAULT 'pending',
		first_seen_at    DATETIME,
		last_seen_at     DATETIME,
		last_notified_at DATETIME,
		created_at       DATETIME,
		resolved_at      DATETIME
	)`).Error; err != nil {
		t.Fatalf("failed to create kube_alarms: %v", err)
	}
	if err := db.Exec(`CREATE TABLE kube_whitelists (
		tenant_id TEXT NOT NULL DEFAULT 't-default',
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		name         TEXT NOT NULL,
		cluster_id   INTEGER,
		cluster_name TEXT,
		alarm_types  TEXT,
		namespace    TEXT,
		pod_pattern  TEXT,
		status       TEXT NOT NULL DEFAULT 'enabled',
		hit_count    INTEGER DEFAULT 0,
		remark       TEXT,
		created_at   DATETIME,
		updated_at   DATETIME
	)`).Error; err != nil {
		t.Fatalf("failed to create kube_whitelists: %v", err)
	}
	return db, NewKubeAlarmService(db, zap.NewNop())
}

// TestGenerateFingerprint 测试指纹生成：相同输入产生相同指纹，任一字段变化指纹不同
func TestGenerateFingerprint(t *testing.T) {
	base := &model.KubeAlarm{
		ClusterID: 1,
		RuleID:    "K8S-001",
		Namespace: "default",
		Target:    "pods/nginx",
	}
	baseFp := generateFingerprint(base)

	if len(baseFp) != 32 {
		t.Errorf("指纹长度应为 32 字符，实际 %d", len(baseFp))
	}

	// 相同输入 → 相同指纹
	if generateFingerprint(base) != baseFp {
		t.Errorf("相同输入应生成相同指纹")
	}

	// 任一字段变化指纹不同
	cases := []struct {
		name  string
		alarm *model.KubeAlarm
	}{
		{"ClusterID 不同", &model.KubeAlarm{ClusterID: 2, RuleID: "K8S-001", Namespace: "default", Target: "pods/nginx"}},
		{"RuleID 不同", &model.KubeAlarm{ClusterID: 1, RuleID: "K8S-002", Namespace: "default", Target: "pods/nginx"}},
		{"Namespace 不同", &model.KubeAlarm{ClusterID: 1, RuleID: "K8S-001", Namespace: "prod", Target: "pods/nginx"}},
		{"Target 不同", &model.KubeAlarm{ClusterID: 1, RuleID: "K8S-001", Namespace: "default", Target: "pods/redis"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if generateFingerprint(c.alarm) == baseFp {
				t.Errorf("字段变化应产生不同指纹")
			}
		})
	}
}

// TestCreateAlarmWithFilter_Dedup 测试 UPSERT 去重：首次创建后，再次调用累加 Count 而非新增行
func TestCreateAlarmWithFilter_Dedup(t *testing.T) {
	db, svc := setupAlarmFilterTestDB(t)

	build := func() *model.KubeAlarm {
		return &model.KubeAlarm{
			ClusterID:   1,
			ClusterName: "c1",
			Severity:    "high",
			AlarmType:   model.KubeAlarmTypeAbnormalProcess,
			RuleID:      "K8S-001",
			Title:       "[K8S-001] exec",
			Message:     "msg",
			Namespace:   "default",
			PodName:     "nginx",
			Target:      "pods/nginx",
			RawData:     model.RawJSON(`{}`),
			Status:      model.KubeAlarmStatusPending,
		}
	}

	// 第一次 → 创建
	first := build()
	created, err := svc.CreateAlarmWithFilter(first)
	if err != nil {
		t.Fatalf("first create err: %v", err)
	}
	if !created {
		t.Errorf("首次调用应返回 created=true")
	}

	var count int64
	db.Model(&model.KubeAlarm{}).Count(&count)
	if count != 1 {
		t.Errorf("首次调用后应有 1 行，实际 %d", count)
	}

	// 第二次（同指纹）→ 更新，不新增
	second := build()
	created2, err := svc.CreateAlarmWithFilter(second)
	if err != nil {
		t.Fatalf("second create err: %v", err)
	}
	if created2 {
		t.Errorf("同指纹重复调用应返回 created=false")
	}

	db.Model(&model.KubeAlarm{}).Count(&count)
	if count != 1 {
		t.Errorf("去重后应仍为 1 行，实际 %d", count)
	}

	var row model.KubeAlarm
	db.First(&row)
	if row.Count != 2 {
		t.Errorf("count 应累加到 2，实际 %d", row.Count)
	}
	if row.Fingerprint == "" {
		t.Error("fingerprint 应被写入")
	}

	// 不同 target → 新增一行
	third := build()
	third.Target = "pods/redis"
	third.PodName = "redis"
	created3, err := svc.CreateAlarmWithFilter(third)
	if err != nil {
		t.Fatalf("third create err: %v", err)
	}
	if !created3 {
		t.Errorf("不同指纹应返回 created=true")
	}
	db.Model(&model.KubeAlarm{}).Count(&count)
	if count != 2 {
		t.Errorf("不同 target 后应有 2 行，实际 %d", count)
	}
}

// TestAlertStormScenario 告警风暴场景：验证误报治理效果
// 模拟真实集群的 168 个审计事件，期望经规则 + 全局排除 + 指纹去重后只产生 3 条告警
func TestAlertStormScenario(t *testing.T) {
	db, svc := setupAlarmFilterTestDB(t)
	detector := &KubeDetector{
		db:           db,
		logger:       zap.NewNop(),
		alarmService: svc,
	}
	detector.registerRules()

	// 场景 1：kubelet 读 Secret（K8S-004）× 100
	// 期望：全局用户排除 → 0 条告警
	for i := 0; i < 100; i++ {
		detector.DetectAuditEvent(1, "c1", &model.AuditEvent{
			Verb:      "get",
			User:      model.AuditUser{Username: fmt.Sprintf("system:node:worker-%d", i%3+1)},
			UserAgent: "kubelet/v1.28.0",
			ObjectRef: &model.AuditObjectRef{Resource: "secrets", Name: "ca", Namespace: "default"},
		})
	}

	// 场景 2：kube-system 创建 hostNetwork Pod（K8S-002）× 50
	// 期望：全局命名空间排除 → 0 条告警
	for i := 0; i < 50; i++ {
		detector.DetectAuditEvent(1, "c1", &model.AuditEvent{
			Verb:       "create",
			User:       model.AuditUser{Username: "system:serviceaccount:kube-system:calico"},
			ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: fmt.Sprintf("calico-%d", i), Namespace: "kube-system"},
			RequestObj: json.RawMessage(`{"spec":{"hostNetwork":true}}`),
		})
	}

	// 场景 3：普通用户在 default 执行 exec bash（K8S-001 + K8S-007 同时命中）× 10
	// 期望：每条规则各 1 条告警 count=10，共 2 条
	for i := 0; i < 10; i++ {
		detector.DetectAuditEvent(1, "c1", &model.AuditEvent{
			Verb:       "create",
			User:       model.AuditUser{Username: "alice"},
			UserAgent:  "kubectl/v1.28.0",
			ObjectRef:  &model.AuditObjectRef{Resource: "pods", Name: "victim", Namespace: "default", Subresource: "exec"},
			RequestObj: json.RawMessage(`{"command":["/bin/bash","-i"]}`),
		})
	}

	// 场景 4：绑定 view 角色的 CRB（K8S-003）× 5
	// 期望：非高权限 → 0 条告警
	for i := 0; i < 5; i++ {
		detector.DetectAuditEvent(1, "c1", &model.AuditEvent{
			Verb:       "create",
			User:       model.AuditUser{Username: "alice"},
			ObjectRef:  &model.AuditObjectRef{Resource: "clusterrolebindings", Name: fmt.Sprintf("viewer-%d", i)},
			RequestObj: json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"view"}}`),
		})
	}

	// 场景 5：绑定 cluster-admin 的 CRB（K8S-003）× 3（相同 binding name → 同指纹）
	// 期望：1 条告警 count=3
	for i := 0; i < 3; i++ {
		detector.DetectAuditEvent(1, "c1", &model.AuditEvent{
			Verb:       "create",
			User:       model.AuditUser{Username: "hacker"},
			ObjectRef:  &model.AuditObjectRef{Resource: "clusterrolebindings", Name: "evil-binding"},
			RequestObj: json.RawMessage(`{"roleRef":{"kind":"ClusterRole","name":"cluster-admin"}}`),
		})
	}

	// 断言：最终只有 3 条告警
	var total int64
	db.Model(&model.KubeAlarm{}).Count(&total)
	if total != 3 {
		t.Errorf("期望产生 3 条告警（降噪后），实际 %d", total)
		// debug 输出
		var all []model.KubeAlarm
		db.Find(&all)
		for _, a := range all {
			t.Logf("  [%s] rule=%s ns=%s target=%s count=%d", a.Title, a.RuleID, a.Namespace, a.Target, a.Count)
		}
		return
	}

	// 按 rule_id 聚合验证 count
	expects := map[string]int{
		"K8S-001": 10, // 场景 3 exec
		"K8S-007": 10, // 场景 3 反弹 shell
		"K8S-003": 3,  // 场景 5 cluster-admin
	}
	for ruleID, expectCount := range expects {
		var row model.KubeAlarm
		if err := db.Where("rule_id = ?", ruleID).First(&row).Error; err != nil {
			t.Errorf("规则 %s 应有一条告警: %v", ruleID, err)
			continue
		}
		if row.Count != expectCount {
			t.Errorf("规则 %s count 期望 %d，实际 %d", ruleID, expectCount, row.Count)
		}
	}
}

// TestMatchPattern 验证白名单通配符/正则匹配
func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{"精确匹配", "nginx-pod", "nginx-pod", true},
		{"精确不匹配", "nginx-pod", "redis-pod", false},
		{"通配符 *", "nginx-*", "nginx-abc", true},
		{"通配符不匹配", "nginx-*", "redis-abc", false},
		{"通配符中间位置", "app-*-worker", "app-v2-worker", true},
		{"多通配符", "*-nginx-*", "prod-nginx-pod1", true},
		{"正则表达式", "^nginx-[0-9]+$", "nginx-123", true},
		{"正则不匹配", "^nginx-[0-9]+$", "nginx-abc", false},
		{"非法正则回退", "[invalid", "[invalid", false},
		{"空 pattern", "", "", true},
		{"单 * 匹配任何", "*", "anything", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// TestWhitelistHitCountUpdate 验证白名单命中时 hit_count 正确递增
func TestWhitelistHitCountUpdate(t *testing.T) {
	db, svc := setupAlarmFilterTestDB(t)

	// 插入白名单规则
	db.Exec(`INSERT INTO kube_whitelists (name, namespace, status, hit_count) VALUES (?, ?, ?, ?)`,
		"test-rule", "kube-system", "enabled", 0)

	alarm := &model.KubeAlarm{
		ClusterID: 1,
		Severity:  "medium",
		AlarmType: model.KubeAlarmTypeAbnormalProcess,
		RuleID:    "K8S-001",
		Namespace: "kube-system",
		Target:    "pods/test",
	}

	// 应命中白名单
	created, err := svc.CreateAlarmWithFilter(alarm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Error("白名单命中应返回 created=false")
	}

	// 验证 hit_count 递增
	var hitCount int
	db.Model(&model.KubeWhitelist{}).Select("hit_count").Where("name = ?", "test-rule").Scan(&hitCount)
	if hitCount != 1 {
		t.Errorf("hit_count 应为 1，实际 %d", hitCount)
	}

	// 再次命中
	_, _ = svc.CreateAlarmWithFilter(alarm)
	db.Model(&model.KubeWhitelist{}).Select("hit_count").Where("name = ?", "test-rule").Scan(&hitCount)
	if hitCount != 2 {
		t.Errorf("hit_count 应为 2，实际 %d", hitCount)
	}
}
