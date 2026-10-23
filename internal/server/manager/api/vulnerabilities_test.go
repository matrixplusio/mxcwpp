package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestListVulnerabilitiesWithHostFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupTestDB(t)
	now := model.LocalTime(time.Now())

	if err := db.Create(&model.Vulnerability{
		ID:             1,
		CveID:          "CVE-2026-1234",
		Severity:       "high",
		CvssScore:      8.8,
		Component:      "nginx",
		Description:    "nginx test vulnerability",
		AffectedHosts:  2,
		Status:         "unpatched",
		DiscoveredAt:   now,
		CurrentVersion: "1.25.0",
		FixedVersion:   "1.25.1",
		ReferenceURL:   "https://example.com/CVE-2026-1234",
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create vulnerability: %v", err)
	}

	if err := db.Create(&model.HostVulnerability{
		ID:             1,
		VulnID:         1,
		HostID:         "host-1",
		Hostname:       "web-01",
		IP:             "10.0.0.1",
		CurrentVersion: "1.25.0",
		Status:         "unpatched",
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create host vulnerability: %v", err)
	}

	if err := db.Create(&model.HostVulnerability{
		ID:             2,
		VulnID:         1,
		HostID:         "host-2",
		Hostname:       "web-02",
		IP:             "10.0.0.2",
		CurrentVersion: "1.25.0",
		Status:         "unpatched",
		CreatedAt:      now,
		UpdatedAt:      now,
	}).Error; err != nil {
		t.Fatalf("failed to create second host vulnerability: %v", err)
	}

	handler := NewVulnerabilitiesHandler(db, zap.NewNop())
	router := gin.New()
	router.GET("/vulnerabilities", handler.ListVulnerabilities)

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/vulnerabilities?host_id=host-1&component=nginx", nil)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Code int `json:"code"`
		Data struct {
			Total int                   `json:"total"`
			Items []model.Vulnerability `json:"items"`
			Stats struct {
				Total         int `json:"total"`
				Critical      int `json:"critical"`
				High          int `json:"high"`
				AffectedHosts int `json:"affectedHosts"`
			} `json:"stats"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Data.Total != 1 {
		t.Fatalf("total = %d, want 1", response.Data.Total)
	}
	if len(response.Data.Items) != 1 {
		t.Fatalf("items len = %d, want 1", len(response.Data.Items))
	}
	if response.Data.Items[0].AffectedHosts != 1 {
		t.Fatalf("affected hosts = %d, want 1", response.Data.Items[0].AffectedHosts)
	}
	if len(response.Data.Items[0].Hosts) != 1 || response.Data.Items[0].Hosts[0].HostID != "host-1" {
		t.Fatalf("unexpected hosts payload: %+v", response.Data.Items[0].Hosts)
	}
	if response.Data.Stats.Total != 1 || response.Data.Stats.High != 1 || response.Data.Stats.AffectedHosts != 1 {
		t.Fatalf("unexpected stats: %+v", response.Data.Stats)
	}
}

// TestListVulnerabilities_PatchedFilterInstanceLevel 验证列表页"已修复"筛选走实例级。
// CVE 级 vulnerabilities.status 停在 unpatched（只 1 台主机修好，未全队列修复），
// 旧实现按 vulnerabilities.status='patched' 筛会返回空 —— 修复页显示已修 >0 但列表筛已修看不到。
// 新实现按 EXISTS host_vulnerabilities.status='patched' 命中，能看到该 CVE。
func TestListVulnerabilities_PatchedFilterInstanceLevel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)
	now := model.LocalTime(time.Now())

	if err := db.Create(&model.Vulnerability{
		ID: 1, CveID: "CVE-2026-9001", Severity: "high", Component: "vim",
		Status: "unpatched", DiscoveredAt: now, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("create vuln: %v", err)
	}
	// 同一 CVE：host-1 已修、host-2 未修（CVE 级仍 unpatched）
	if err := db.Create(&model.HostVulnerability{
		ID: 1, VulnID: 1, HostID: "host-1", Hostname: "web-01", Status: "patched", PatchedAt: &now, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("create hv1: %v", err)
	}
	if err := db.Create(&model.HostVulnerability{
		ID: 2, VulnID: 1, HostID: "host-2", Hostname: "web-02", Status: "unpatched", CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("create hv2: %v", err)
	}

	handler := NewVulnerabilitiesHandler(db, zap.NewNop())
	router := gin.New()
	router.GET("/vulnerabilities", handler.ListVulnerabilities)

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/vulnerabilities?status=patched", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Data struct {
			Total int                   `json:"total"`
			Items []model.Vulnerability `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if response.Data.Total != 1 || len(response.Data.Items) != 1 {
		t.Fatalf("patched filter total=%d items=%d, want 1/1 (instance-level, not CVE-level)", response.Data.Total, len(response.Data.Items))
	}
	// 展示状态应与筛选口径一致
	if response.Data.Items[0].Status != "patched" {
		t.Fatalf("displayed status = %q, want patched", response.Data.Items[0].Status)
	}
}

// TestListVulnerabilities_PackageTypeFilter 验证包类型过滤:
// 默认(不传)只显示 OS 发行版包漏洞(source!=osv), 屏蔽应用依赖(osv);
// package_type=app 只显示应用依赖; package_type=all 显示全部。
func TestListVulnerabilities_PackageTypeFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)
	now := model.LocalTime(time.Now())

	// OS 包漏洞(rhsa) + 应用依赖漏洞(osv), 各挂一台主机实例。
	seed := []struct {
		id     uint
		cve    string
		source string
	}{
		{1, "CVE-2026-OS01", "rhsa"},
		{2, "CVE-2026-APP1", "osv"},
	}
	for _, s := range seed {
		if err := db.Create(&model.Vulnerability{
			ID: s.id, CveID: s.cve, Severity: "high", Component: "pkg", Source: s.source,
			Status: "unpatched", DiscoveredAt: now, CreatedAt: now, UpdatedAt: now,
		}).Error; err != nil {
			t.Fatalf("create vuln %s: %v", s.cve, err)
		}
		if err := db.Create(&model.HostVulnerability{
			ID: s.id, VulnID: s.id, HostID: "host-1", Status: "unpatched",
			CreatedAt: now, UpdatedAt: now,
		}).Error; err != nil {
			t.Fatalf("create host vuln %s: %v", s.cve, err)
		}
	}

	handler := NewVulnerabilitiesHandler(db, zap.NewNop())
	router := gin.New()
	router.GET("/vulnerabilities", handler.ListVulnerabilities)

	query := func(q string) []model.Vulnerability {
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/vulnerabilities"+q, nil)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				Items []model.Vulnerability `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("parse: %v", err)
		}
		return resp.Data.Items
	}

	// 默认 = os: 只见 OS 包漏洞。
	def := query("")
	if len(def) != 1 || def[0].CveID != "CVE-2026-OS01" {
		t.Fatalf("default(os) items = %+v, want only CVE-2026-OS01", def)
	}
	// app: 只见应用依赖。
	app := query("?package_type=app")
	if len(app) != 1 || app[0].CveID != "CVE-2026-APP1" {
		t.Fatalf("app items = %+v, want only CVE-2026-APP1", app)
	}
	// all: 全部。
	all := query("?package_type=all")
	if len(all) != 2 {
		t.Fatalf("all items len = %d, want 2", len(all))
	}
}
