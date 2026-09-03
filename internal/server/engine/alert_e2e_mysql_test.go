package engine

import (
	"os"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Stage 告警的端到端落库验证。不设 PROBE_DSN 时跳过。
//
//	PROBE_DSN='user:pass@tcp(127.0.0.1:3306)/mxcwpp?charset=utf8mb4&parseTime=True&loc=Local' \
//	    go test ./internal/server/engine/ -run E2EMySQL
//
// 为什么要单独验这条：Privilege / RASP 这类 Stage 自己不落库，
// 告警要经 pipeline 的 alertWriter 统一写入 alerts 表，再由 manager 的
// /api/v1/alerts 查出来。中间任何一环断了，Stage 都还在「正常产生告警」，
// 只是没人看得到——这正是 E-WIRE-1 要治的那类断链。
//
// 单测里 Stage 返回了 Alert 只能证明它算出了结果，证明不了那条告警到得了界面。
func alertE2EDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("PROBE_DSN")
	if dsn == "" {
		t.Skip("未设置 PROBE_DSN，跳过端到端落库验证")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("连接 MySQL 失败: %v", err)
	}
	return db
}

func TestStageAlertReachesAlertsTable_E2EMySQL(t *testing.T) {
	db := alertE2EDB(t)
	const hostID = "e2e-stage-host"

	cleanup := func() { db.Where("host_id = ?", hostID).Delete(&model.Alert{}) }
	cleanup()
	t.Cleanup(cleanup)

	w := NewStageAlertWriter(db, zap.NewNop())

	ev := PipelineEvent{HostID: hostID, DataType: 3005}
	alert := Alert{
		RuleID:         "privilege-escalation-e2e",
		Severity:       "high",
		ATTCKTactic:    "TA0004",
		ATTCKTechnique: "T1068",
	}

	if err := w.Persist("privilege", ev, alert); err != nil {
		t.Fatalf("Stage 告警落库失败: %v", err)
	}

	// 从 alerts 表读回——这是 manager 的 /api/v1/alerts 查询的同一张表
	var got model.Alert
	if err := db.Where("host_id = ? AND rule_id = ?", hostID, alert.RuleID).
		First(&got).Error; err != nil {
		t.Fatalf("告警未出现在 alerts 表：%v\n"+
			"Stage 产生了告警但没有落到界面能查到的地方，等于没有检测", err)
	}
	if got.Severity != "high" {
		t.Errorf("严重度应为 high，实际 %q", got.Severity)
	}
	if got.Title == "" {
		t.Error("标题为空——界面上会是一条看不出所以然的告警")
	}
	if got.Status == "" {
		t.Error("状态为空——列表按状态过滤时这条会漏掉")
	}
	t.Logf("已落库：id=%d result_id=%s severity=%s", got.ID, got.ResultID, got.Severity)

	// 同一条重复触发应当去重累加，而不是堆出第二行
	if err := w.Persist("privilege", ev, alert); err != nil {
		t.Fatalf("重复落库失败: %v", err)
	}
	var n int64
	db.Model(&model.Alert{}).Where("host_id = ? AND rule_id = ?", hostID, alert.RuleID).Count(&n)
	if n != 1 {
		t.Fatalf("同一告警重复触发应去重为 1 行，实际 %d 行——界面会被同一件事刷屏", n)
	}
}

// 缺少身份维度的告警必须被拒绝，而不是写进去。
//
// 没有 host_id 或 rule_id 就无法稳定去重，这类行会不断堆积，
// 最终把真实告警淹掉。
func TestStageAlertRejectsIdentitylessAlert_E2EMySQL(t *testing.T) {
	db := alertE2EDB(t)
	w := NewStageAlertWriter(db, zap.NewNop())

	if err := w.Persist("privilege", PipelineEvent{HostID: "h"}, Alert{
		Severity: "high", // 无 rule_id
	}); err == nil {
		t.Fatal("缺 rule_id 的告警必须被拒绝")
	}
	if err := w.Persist("privilege", PipelineEvent{}, Alert{
		RuleID: "r1", Severity: "high", // 无 host_id
	}); err == nil {
		t.Fatal("缺 host_id 的告警必须被拒绝")
	}
}
