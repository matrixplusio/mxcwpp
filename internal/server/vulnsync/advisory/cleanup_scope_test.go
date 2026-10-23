package advisory

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func scopeDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	for _, ddl := range []string{
		`CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY, source TEXT, updated_at DATETIME)`,
		`CREATE TABLE host_vulnerabilities (id INTEGER PRIMARY KEY, vuln_id INTEGER, host_id TEXT)`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

const badSource = `
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
WHERE v.source = ?`

func remainingIDs(t *testing.T, db *gorm.DB) []uint {
	t.Helper()
	var ids []uint
	db.Raw(`SELECT id FROM host_vulnerabilities ORDER BY id`).Scan(&ids)
	return ids
}

// 增量范围只动两类关联：新建的（id 大于水位），以及漏洞在水位时刻之后被更新过的。
// 其余命中条件的旧关联留给全量那一轮——它们在上一轮全量时并不命中，这期间条件没变。
func TestPurgeHostVulnFPIncrementalScope(t *testing.T) {
	db := scopeDB(t)
	now := time.Now()
	old, recent := now.Add(-2*time.Hour), now.Add(-time.Minute)
	db.Exec(`INSERT INTO vulnerabilities VALUES (1,'bad',?), (2,'bad',?), (3,'good',?)`, old, recent, recent)
	db.Exec(`INSERT INTO host_vulnerabilities VALUES
		(10,1,'h1'),  -- 旧关联、漏洞未更新：增量不碰
		(11,2,'h1'),  -- 旧关联、漏洞刚更新：命中
		(20,1,'h2'),  -- 新关联：命中
		(21,3,'h2')   -- 新关联但不满足条件：保留`)

	sc := CleanupScope{MinHostVulnID: 15, VulnUpdatedSince: now.Add(-10 * time.Minute)}
	n, err := purgeHostVulnFP(db, zap.NewNop(), sc, badSource, "bad")
	if err != nil || n != 2 {
		t.Fatalf("增量应删 2 条，得 %d err=%v", n, err)
	}
	if got := remainingIDs(t, db); len(got) != 2 || got[0] != 10 || got[1] != 21 {
		t.Errorf("应剩 [10 21]，得 %v", got)
	}

	// 全量把剩下那条旧的也清掉，不满足条件的仍保留。
	n, err = purgeHostVulnFP(db, zap.NewNop(), CleanupScope{Full: true}, badSource, "bad")
	if err != nil || n != 1 {
		t.Fatalf("全量应再删 1 条，得 %d err=%v", n, err)
	}
	if got := remainingIDs(t, db); len(got) != 1 || got[0] != 21 {
		t.Errorf("应只剩 [21]，得 %v", got)
	}
}

// 同一条关联同时满足「新建」与「漏洞刚更新」时只删一次、计一次。
func TestPurgeHostVulnFPDedupsOverlap(t *testing.T) {
	db := scopeDB(t)
	now := time.Now()
	db.Exec(`INSERT INTO vulnerabilities VALUES (1,'bad',?)`, now)
	db.Exec(`INSERT INTO host_vulnerabilities VALUES (30,1,'h1')`)
	n, err := purgeHostVulnFP(db, zap.NewNop(), CleanupScope{MinHostVulnID: 0, VulnUpdatedSince: now.Add(-time.Hour)}, badSource, "bad")
	if err != nil || n != 1 {
		t.Errorf("应删 1 条，得 %d err=%v", n, err)
	}
}

// 按漏洞更新时间筛选的那一路要改成从漏洞表驱动；片段写法对不上时原样返回。
func TestToVulnFirst(t *testing.T) {
	got := toVulnFirst(badSource)
	want := `
FROM vulnerabilities v
STRAIGHT_JOIN host_vulnerabilities hv ON hv.vuln_id = v.id
WHERE v.source = ?`
	if got != want {
		t.Errorf("改写结果不对：%q", got)
	}
	other := "FROM x JOIN y ON 1=1 WHERE 1=1"
	if toVulnFirst(other) != other {
		t.Error("不是预期写法的片段应原样返回")
	}
}
