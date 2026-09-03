package biz

import (
	"os"
	"testing"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 针对真实 MySQL 的清理逻辑验证。不设 PROBE_DSN 时自动跳过。
//
//	PROBE_DSN='user:pass@tcp(127.0.0.1:3306)/mxcwpp?charset=utf8mb4&parseTime=True&loc=Local' \
//	    go test ./internal/server/manager/biz/ -run MySQL
//
// 为什么必须跑真库：这条缺陷是方言差异。sqlite 接受没有 LIMIT 的 OFFSET，
// MySQL 直接拒绝（Error 1064）。原实现在 sqlite 单测下完全正常，
// 在生产上却从未成功清理过一次——错误被 gorm 记在 info 级别，
// 表面看不出异常，任务与结果表一路涨到 204 / 15090 行。
func TestPruneOldTasksMySQLDialect(t *testing.T) {
	dsn := os.Getenv("PROBE_DSN")
	if dsn == "" {
		t.Skip("未设置 PROBE_DSN，跳过 MySQL 集成验证")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("连接 MySQL 失败: %v", err)
	}

	// 只读验证：分界查询必须能在 MySQL 上执行成功。
	// 断言点不是"删了多少"（那依赖库里的数据），而是"这条 SQL 能跑"——
	// 缺陷正是它跑不了。
	var boundary []uint
	err = db.Model(&model.KubeBaselineTask{}).
		Where("cluster_id = ?", 1).
		Order("id DESC").Limit(1).Offset(9).
		Pluck("id", &boundary).Error
	if err != nil {
		t.Fatalf("分界查询在 MySQL 上失败: %v", err)
	}

	// 反向确认：不带 LIMIT 的 OFFSET 在 MySQL 上必然报错。
	// 这条断言的作用是，如果哪天有人把 Limit(1) 去掉，测试会告诉他为什么不能去。
	var ids []uint
	err = db.Model(&model.KubeBaselineTask{}).
		Where("cluster_id = ?", 1).
		Order("id DESC").Offset(9).
		Pluck("id", &ids).Error
	if err == nil {
		t.Error("MySQL 应当拒绝没有 LIMIT 的 OFFSET；若此处通过，说明前提变了，清理写法可以简化")
	}
}
