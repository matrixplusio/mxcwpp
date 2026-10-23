package remediation

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// 结果回来时关联已被删除：丢弃并返回 nil，不当成写入失败（否则进死信，重放也不会成功）。
// 关联存在但不属于上报的主机，仍然是错误。
func TestHandleResultStaleHostVuln(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE host_vulnerabilities (id INTEGER PRIMARY KEY, host_id TEXT)`).Error; err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO host_vulnerabilities VALUES (7, 'other-host')`)
	h := NewPreCheckResultHandler(db, zap.NewNop())

	if err := h.HandleResult("h1", map[string]string{"host_vuln_id": "999", "status": "available"}); err != nil {
		t.Errorf("关联已不存在应丢弃而不是报错，得 %v", err)
	}
	if err := h.HandleResult("h1", map[string]string{"host_vuln_id": "7", "status": "available"}); err == nil {
		t.Error("关联属于别的主机时必须报错")
	}
}
