package biz

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func kubeVulnDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.ImageScan{}, &model.ImageVulnerability{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func vulnReport(uid, version string, cves ...string) *unstructured.Unstructured {
	vs := make([]any, 0, len(cves))
	for _, c := range cves {
		vs = append(vs, map[string]any{"vulnerabilityID": c, "resource": "openssl", "severity": "HIGH"})
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"report": map[string]any{
			"artifact":        map[string]any{"repository": "library/nginx", "tag": "1.25"},
			"vulnerabilities": vs,
		},
	}}
	u.SetUID(types.UID(uid))
	u.SetResourceVersion(version)
	return u
}

func apply(t *testing.T, db *gorm.DB, u *unstructured.Unstructured) bool {
	t.Helper()
	scan, vulns := parseVulnReport(1, u)
	applied, err := applyReport(db, 1, scan, vulns)
	if err != nil {
		t.Fatal(err)
	}
	return applied
}

func countRows(t *testing.T, db *gorm.DB) (scans, vulns int64) {
	t.Helper()
	db.Model(&model.ImageScan{}).Count(&scans)
	db.Model(&model.ImageVulnerability{}).Count(&vulns)
	return
}

// 报告版本没变就不重写；变了只替换这一份，不留旧行。
// 原先每轮同步都把整集群删光重插，绝大多数报告根本没变。
func TestApplyReportSkipsUnchanged(t *testing.T) {
	db := kubeVulnDB(t)

	if !apply(t, db, vulnReport("u1", "10", "CVE-1", "CVE-2")) {
		t.Fatal("首次应写入")
	}
	var first model.ImageScan
	db.First(&first)

	if apply(t, db, vulnReport("u1", "10", "CVE-1", "CVE-2")) {
		t.Error("版本未变不应重写")
	}
	var again model.ImageScan
	db.First(&again)
	if again.ID != first.ID {
		t.Error("版本未变时记录被替换了")
	}

	if !apply(t, db, vulnReport("u1", "11", "CVE-3")) {
		t.Error("版本变化应重写")
	}
	if scans, vulns := countRows(t, db); scans != 1 || vulns != 1 {
		t.Errorf("替换后应只剩 1 条扫描 1 条漏洞，得 %d / %d", scans, vulns)
	}
}

// 集群里已不存在的报告与没有 uid 的旧数据要清掉，仍在的保留。
func TestPruneClusterScans(t *testing.T) {
	db := kubeVulnDB(t)
	apply(t, db, vulnReport("keep", "1", "CVE-1"))
	apply(t, db, vulnReport("gone", "1", "CVE-2"))
	cid := uint(1)
	legacy := &model.ImageScan{Image: "old", ClusterID: &cid, Source: "cluster"}
	if err := insertScan(db, legacy, []model.ImageVulnerability{{CveID: "CVE-9"}}); err != nil {
		t.Fatal(err)
	}

	removed, err := pruneClusterScans(db, 1, []string{"keep"})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Errorf("应删除 2 条（消失的与旧数据），得 %d", removed)
	}
	var left []string
	db.Model(&model.ImageScan{}).Pluck("report_uid", &left)
	if len(left) != 1 || left[0] != "keep" {
		t.Errorf("应只剩 keep，得 %v", left)
	}
	if _, vulns := countRows(t, db); vulns != 1 {
		t.Errorf("被删扫描的漏洞行要一并删除，剩 %d", vulns)
	}
}
