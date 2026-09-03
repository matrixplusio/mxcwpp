package kube

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// openMemDB 打开单连接 SQLite 内存库（:memory: 每连接独立，需限连接池为 1）。
func openMemDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	return db
}

// excludedAuditEvent 返回命名空间在排除名单(kube-system)内的事件，
// 使 DetectAuditEvent 提前 return，从而无需构建告警服务即可专测持久化路径。
func excludedAuditEvent() model.AuditEvent {
	return model.AuditEvent{
		Stage: "ResponseComplete",
		Verb:  "get",
		ObjectRef: &model.AuditObjectRef{
			Namespace: "kube-system",
			Resource:  "pods",
		},
	}
}

// TestProcessAuditEvents_WriteFailureReturnsError 验证：kube_events 表缺失导致 Create 失败时
// ProcessAuditEvents 返回非 nil error（供 Pub/Sub 路径据此 Nack 重投，修复原 at-most-once 丢数据缺陷）。
func TestProcessAuditEvents_WriteFailureReturnsError(t *testing.T) {
	db := openMemDB(t) // 不建 kube_events 表 → Create 必失败
	p := NewKubeAuditProcessor(db, zap.NewNop(), nil)

	err := p.ProcessAuditEvents(model.KubeCluster{}, []model.AuditEvent{excludedAuditEvent()})
	if err == nil {
		t.Fatal("持久化失败时 ProcessAuditEvents 应返回错误，实际返回 nil")
	}
}

// TestProcessAuditEvents_SuccessReturnsNil 验证：表存在、写入成功时返回 nil（供 Pub/Sub 路径 Ack）。
func TestProcessAuditEvents_SuccessReturnsNil(t *testing.T) {
	db := openMemDB(t)
	if err := db.AutoMigrate(&model.KubeEvent{}); err != nil {
		t.Fatalf("migrate kube_events: %v", err)
	}
	p := NewKubeAuditProcessor(db, zap.NewNop(), nil)

	if err := p.ProcessAuditEvents(model.KubeCluster{}, []model.AuditEvent{excludedAuditEvent()}); err != nil {
		t.Fatalf("写入成功应返回 nil，实际: %v", err)
	}

	var count int64
	db.Model(&model.KubeEvent{}).Count(&count)
	if count != 1 {
		t.Fatalf("应持久化 1 条 kube_event，实际 %d", count)
	}
}
