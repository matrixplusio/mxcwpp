package advisory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestIsRetryableDBError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&mysql.MySQLError{Number: 1205}, true},
		{&mysql.MySQLError{Number: 1213}, true},
		{fmt.Errorf("upsert: %w", &mysql.MySQLError{Number: 1213}), true},
		{mysql.ErrInvalidConn, true},
		// 数据库故障一律可重试：连接被拒、连接数满、只读、服务器关闭、超时。
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{&mysql.MySQLError{Number: 1040}, true},
		{&mysql.MySQLError{Number: 1290}, true},
		{&mysql.MySQLError{Number: 1053}, true},
		{context.DeadlineExceeded, true},
		{errors.New("boom"), true},
		// 只有明确的数据错误不可重试。
		{&mysql.MySQLError{Number: 1062}, false},
		{&mysql.MySQLError{Number: 1406}, false},
		{fmt.Errorf("x: %w", &mysql.MySQLError{Number: 1366}), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := IsRetryableDBError(c.err); got != c.want {
			t.Errorf("IsRetryableDBError(%v) = %v，应为 %v", c.err, got, c.want)
		}
	}
}

func fastRetry(t *testing.T) {
	old := writeRetryBase
	writeRetryBase = time.Millisecond
	t.Cleanup(func() { writeRetryBase = old })
}

// 可重试错误重试到成功；不可重试的不重试。
func TestWithRetry(t *testing.T) {
	fastRetry(t)
	n := 0
	err := withRetry(func() error {
		n++
		if n < 3 {
			return &mysql.MySQLError{Number: 1213}
		}
		return nil
	})
	if err != nil || n != 3 {
		t.Errorf("应在第 3 次成功，实际 n=%d err=%v", n, err)
	}
	n = 0
	_ = withRetry(func() error { n++; return &mysql.MySQLError{Number: 1062} })
	if n != 1 {
		t.Errorf("不可重试错误不应重试，实际执行 %d 次", n)
	}
	n = 0
	err = withRetry(func() error { n++; return &mysql.MySQLError{Number: 1205} })
	if n != writeRetries+1 || !IsRetryableDBError(err) {
		t.Errorf("一直失败应执行 %d 次并返回可重试错误，实际 %d 次 err=%v", writeRetries+1, n, err)
	}
}

// mergedWithPackages 构造 n 个 CVE、每个一行 advisory_packages 的合并结果。
func mergedWithPackages(n int) map[string]*mergedVuln {
	merged := make(map[string]*mergedVuln, n)
	for i := 0; i < n; i++ {
		cve := fmt.Sprintf("CVE-2026-%05d", i)
		adv := &Advisory{AdvisoryID: "A-" + cve, CVEIDs: []string{cve}, OSFamily: "rhel", OSMajorVer: "9",
			AffectedPkgs: []PkgFix{{Name: "pkg", Arch: "x86_64", FixedVersion: "1.0"}}}
		merged[cve] = &mergedVuln{advisory: adv,
			allAdvisories: []sourcedAdvisory{{sourceName: "rhsa", advisory: adv, confidence: ConfidenceHigh}}}
	}
	return merged
}

// newAPDB 建一个只含 advisory_packages（带 6 列唯一索引，upsert 依赖它）的 sqlite。
func newAPDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&model.AdvisoryPackage{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uk_ap ON advisory_packages (cve_id, source, os_family, os_major, pkg_name, arch)").Error; err != nil {
		t.Fatal(err)
	}
	return db
}

// injectCreateError 在 advisory_packages 的 INSERT 上注入错误：pick 返回非 nil 时这一批失败。
func injectCreateError(t *testing.T, db *gorm.DB, pick func(rows []model.AdvisoryPackage) error) {
	t.Helper()
	if err := db.Callback().Create().Before("gorm:create").Register("test:inject", func(tx *gorm.DB) {
		if rows, ok := tx.Statement.Dest.(*[]model.AdvisoryPackage); ok {
			if err := pick(*rows); err != nil {
				_ = tx.AddError(err)
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func countAP(t *testing.T, db *gorm.DB) int64 {
	var n int64
	if err := db.Model(&model.AdvisoryPackage{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// 某一批遇到数据错误：逐行重写这一批，只跳过真正的坏行，其余照常写入。
func TestBulkUpsertSkipsOnlyBadRow(t *testing.T) {
	fastRetry(t)
	db := newAPDB(t)
	injectCreateError(t, db, func(rows []model.AdvisoryPackage) error {
		for _, r := range rows {
			if r.CveID == "CVE-2026-00500" { // 排序后落在第二批
				return &mysql.MySQLError{Number: 1406, Message: "Data too long"}
			}
		}
		return nil
	})
	c := NewCoordinator(db, zap.NewNop())
	written, skipped, err := c.bulkUpsertAdvisoryPackages(mergedWithPackages(1200))
	if err != nil {
		t.Fatalf("不可重试错误不应交给调用方重做: %v", err)
	}
	if written != 1199 || skipped != 1 || countAP(t, db) != 1199 {
		t.Errorf("应写 1199、只跳过坏的 1 行，实际 written=%d skipped=%d 库中 %d", written, skipped, countAP(t, db))
	}
}

// 可重试错误：重试成功则全部写入；一直失败则把错误交给调用方整批重做。
func TestBulkUpsertRetryableErrors(t *testing.T) {
	fastRetry(t)
	db := newAPDB(t)
	fails := 2
	injectCreateError(t, db, func(rows []model.AdvisoryPackage) error {
		if rows[0].CveID == "CVE-2026-00000" && fails > 0 {
			fails--
			return &mysql.MySQLError{Number: 1213, Message: "Deadlock"}
		}
		return nil
	})
	c := NewCoordinator(db, zap.NewNop())
	written, _, err := c.bulkUpsertAdvisoryPackages(mergedWithPackages(600))
	if err != nil || written != 600 {
		t.Fatalf("重试后应全部写入，实际 written=%d err=%v", written, err)
	}

	db2 := newAPDB(t)
	injectCreateError(t, db2, func([]model.AdvisoryPackage) error { return &mysql.MySQLError{Number: 1205} })
	_, _, err = NewCoordinator(db2, zap.NewNop()).bulkUpsertAdvisoryPackages(mergedWithPackages(10))
	if !IsRetryableDBError(err) {
		t.Errorf("一直锁超时应返回可重试错误交给调用方，实际 %v", err)
	}
}

// 写入按唯一键排序：并发写入方按同一顺序加锁，避免互相死锁。
func TestAdvisoryPackageKeyOrder(t *testing.T) {
	a := model.AdvisoryPackage{CveID: "CVE-1", Source: "rhsa", OSFamily: "rhel", OSMajor: "9", PkgName: "a", Arch: "x86_64"}
	b := a
	b.PkgName = "b"
	c := a
	c.CveID = "CVE-0"
	if !advisoryPackageKeyLess(&a, &b) || !advisoryPackageKeyLess(&c, &a) || advisoryPackageKeyLess(&a, &a) {
		t.Error("排序应按唯一键逐列比较")
	}
}

// 数据库连不上时整批交给调用方重做，不能被当成数据错误跳过——那会让消费者提交 offset，
// 恰好在数据库故障时把积压一次性丢掉。
func TestBulkUpsertConnRefusedIsRetried(t *testing.T) {
	fastRetry(t)
	db := newAPDB(t)
	injectCreateError(t, db, func([]model.AdvisoryPackage) error {
		return &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	})
	written, skipped, err := NewCoordinator(db, zap.NewNop()).bulkUpsertAdvisoryPackages(mergedWithPackages(10))
	if err == nil || skipped != 0 || written != 0 {
		t.Errorf("连接被拒应返回错误、不跳过，实际 written=%d skipped=%d err=%v", written, skipped, err)
	}
}
