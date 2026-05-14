package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
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
		ReferenceUrl:   "https://example.com/CVE-2026-1234",
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
