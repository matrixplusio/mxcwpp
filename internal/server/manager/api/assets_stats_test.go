package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func seedAssetTestData(t *testing.T) *AssetsHandler {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db := setupTestDB(t)

	now := model.LocalTime(time.Now())
	hostRows := []struct {
		hostID       string
		hostname     string
		ipv4         string
		status       string
		businessLine string
	}{
		{hostID: "host-1", hostname: "web-01", ipv4: `["10.0.0.1"]`, status: "online", businessLine: "payment"},
		{hostID: "host-2", hostname: "cache-01", ipv4: `["10.0.0.2"]`, status: "offline", businessLine: "retail"},
		{hostID: "host-3", hostname: "idle-01", ipv4: `["10.0.0.3"]`, status: "online", businessLine: "payment"},
	}
	for _, row := range hostRows {
		if err := db.Exec(
			`INSERT INTO hosts (host_id, hostname, ipv4, status, business_line) VALUES (?, ?, ?, ?, ?)`,
			row.hostID, row.hostname, row.ipv4, row.status, row.businessLine,
		).Error; err != nil {
			t.Fatalf("failed to seed host test data: %v", err)
		}
	}

	rows := []interface{}{
		&model.Process{ID: "proc-1", HostID: "host-1", PID: "101", PPID: "1", Exe: "/usr/bin/nginx", Cmdline: "nginx: master", Username: "root", ContainerID: "container-1", CollectedAt: now},
		&model.Process{ID: "proc-2", HostID: "host-1", PID: "102", PPID: "1", Exe: "/usr/bin/nginx", Cmdline: "nginx: worker", Username: "www", ContainerID: "container-1", CollectedAt: now},
		&model.Process{ID: "proc-3", HostID: "host-2", PID: "201", PPID: "1", Exe: "/usr/bin/redis-server", Cmdline: "redis-server *:6379", Username: "redis", CollectedAt: now},
		&model.Port{ID: "port-1", HostID: "host-1", Protocol: "tcp", Port: 80, ProcessName: "nginx", PID: "101", ContainerID: "container-1", State: "LISTEN", CollectedAt: now},
		&model.Port{ID: "port-2", HostID: "host-1", Protocol: "tcp", Port: 443, ProcessName: "nginx", PID: "102", ContainerID: "container-1", State: "LISTEN", CollectedAt: now},
		&model.Port{ID: "port-3", HostID: "host-2", Protocol: "tcp", Port: 6379, ProcessName: "redis-server", PID: "201", State: "LISTEN", CollectedAt: now},
		&model.AssetUser{ID: "user-1", HostID: "host-1", Username: "root", UID: "0", GID: "0", HomeDir: "/root", Shell: "/bin/bash", CollectedAt: now},
		&model.AssetUser{ID: "user-2", HostID: "host-2", Username: "redis", UID: "999", GID: "999", HomeDir: "/var/lib/redis", Shell: "/sbin/nologin", CollectedAt: now},
		&model.Software{ID: "soft-1", HostID: "host-1", Name: "nginx", Version: "1.25.0", PackageType: "rpm", CollectedAt: now},
		&model.Software{ID: "soft-2", HostID: "host-2", Name: "redis", Version: "7.2.0", PackageType: "rpm", CollectedAt: now},
		&model.Container{ID: "container-row-1", HostID: "host-1", ContainerID: "container-1", ContainerName: "nginx-gateway", Image: "nginx:1.25.0", Runtime: "docker", Status: "running", CollectedAt: now},
		&model.App{ID: "app-1", HostID: "host-1", AppType: "nginx", AppName: "nginx", Version: "1.25.0", Port: 80, ProcessID: "101", ConfigPath: "/etc/nginx/nginx.conf", CollectedAt: now},
		&model.Service{ID: "svc-1", HostID: "host-1", ServiceName: "nginx", ServiceType: "systemd", Status: "active", CollectedAt: now},
		&model.Cron{ID: "cron-1", HostID: "host-1", User: "root", Schedule: "*/5 * * * *", Command: "/usr/local/bin/backup", CronType: "crontab", CollectedAt: now},
		&model.Vulnerability{ID: 1, CveID: "CVE-2026-0001", Severity: "high", Component: "nginx", Status: "unpatched", FixedVersion: "1.25.1", CreatedAt: now, UpdatedAt: now},
		&model.HostVulnerability{ID: 1, VulnID: 1, HostID: "host-1", Hostname: "web-01", IP: "10.0.0.1", CurrentVersion: "1.25.0", Status: "unpatched", CreatedAt: now, UpdatedAt: now},
		&model.FIMEvent{EventID: "fim-1", HostID: "host-1", Hostname: "web-01", FilePath: "/etc/nginx/nginx.conf", ChangeType: "changed", Severity: "medium", Category: "config", DetectedAt: now, CreatedAt: now},
	}
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("failed to seed asset test data: %v", err)
		}
	}

	return NewAssetsHandler(db, zap.NewNop())
}

func TestAssetsStatistics(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/statistics", handler.GetStatistics)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/statistics?host_id=host-1", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int             `json:"code"`
		Data AssetStatistics `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0", resp.Code)
	}
	if resp.Data.Processes != 2 || resp.Data.Ports != 2 || resp.Data.Users != 1 || resp.Data.Software != 1 || resp.Data.Services != 1 || resp.Data.Crons != 1 {
		t.Fatalf("unexpected statistics: %+v", resp.Data)
	}
}

func TestAssetsOverview(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/overview", handler.GetOverview)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/overview", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int           `json:"code"`
		Data AssetOverview `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0", resp.Code)
	}
	if resp.Data.Scope != "global" {
		t.Fatalf("scope = %q, want global", resp.Data.Scope)
	}
	if resp.Data.TotalHosts != 3 || resp.Data.CoveredHosts != 2 || resp.Data.UncoveredHosts != 1 {
		t.Fatalf("unexpected host coverage: %+v", resp.Data)
	}
	if resp.Data.OnlineHosts != 2 || resp.Data.OfflineHosts != 1 {
		t.Fatalf("unexpected host status counts: %+v", resp.Data)
	}
	if resp.Data.BusinessLineCount != 2 {
		t.Fatalf("business_line_count = %d, want 2", resp.Data.BusinessLineCount)
	}
	if resp.Data.CoverageRate < 66 || resp.Data.CoverageRate > 67 {
		t.Fatalf("coverage_rate = %f, want about 66.67", resp.Data.CoverageRate)
	}
	if resp.Data.LastCollectedAt == "" {
		t.Fatalf("last_collected_at should not be empty")
	}
}

func TestAssetsOverviewWithBusinessLineScope(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/overview", handler.GetOverview)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/overview?business_line=payment", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int           `json:"code"`
		Data AssetOverview `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Data.TotalHosts != 2 || resp.Data.CoveredHosts != 1 || resp.Data.UncoveredHosts != 1 {
		t.Fatalf("unexpected business line coverage: %+v", resp.Data)
	}
	if resp.Data.OnlineHosts != 2 || resp.Data.OfflineHosts != 0 {
		t.Fatalf("unexpected business line host status counts: %+v", resp.Data)
	}
	if resp.Data.BusinessLineCount != 1 {
		t.Fatalf("business_line_count = %d, want 1", resp.Data.BusinessLineCount)
	}
}

func TestAssetHistory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)

	if err := db.Exec(`INSERT INTO hosts (host_id, hostname, ipv4, status, business_line) VALUES (?, ?, ?, ?, ?)`,
		"host-1", "web-01", `["10.0.0.1"]`, "online", "payment",
	).Error; err != nil {
		t.Fatalf("failed to seed host: %v", err)
	}

	// 锚定到当天正午附近：history 按 DATE(collected_at) 聚合，若用 now()/now()-2h，
	// 凌晨时段 now-2h 会跨 UTC 午夜被拆成两天（时区 flaky）。正午 ±1h 在 UTC 与本地都同一天。
	now := time.Now()
	noon := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.UTC)
	oldTime := model.LocalTime(noon.Add(-1 * time.Hour))
	newTime := model.LocalTime(noon)
	rows := []interface{}{
		&model.Process{ID: "hist-proc-1", HostID: "host-1", PID: "101", Exe: "/usr/bin/nginx", Cmdline: "nginx: master", Username: "root", CollectedAt: oldTime},
		&model.Port{ID: "hist-port-1", HostID: "host-1", Protocol: "tcp", Port: 80, PID: "101", ProcessName: "nginx", State: "LISTEN", CollectedAt: oldTime},
		&model.Process{ID: "hist-proc-2", HostID: "host-1", PID: "102", Exe: "/usr/bin/nginx", Cmdline: "nginx: worker", Username: "www", CollectedAt: newTime},
		&model.Process{ID: "hist-proc-3", HostID: "host-1", PID: "103", Exe: "/usr/bin/nginx", Cmdline: "nginx: helper", Username: "www", CollectedAt: newTime},
		&model.Port{ID: "hist-port-2", HostID: "host-1", Protocol: "tcp", Port: 80, PID: "102", ProcessName: "nginx", State: "LISTEN", CollectedAt: newTime},
		&model.Port{ID: "hist-port-3", HostID: "host-1", Protocol: "tcp", Port: 443, PID: "103", ProcessName: "nginx", State: "LISTEN", CollectedAt: newTime},
	}
	for _, row := range rows {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("failed to seed history rows: %v", err)
		}
	}

	handler := NewAssetsHandler(db, zap.NewNop())
	r := gin.New()
	r.GET("/history", handler.GetHistory)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/history?host_id=host-1&days=7&limit=10", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int                `json:"code"`
		Data AssetHistoryResult `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0", resp.Code)
	}
	if resp.Data.Scope != "host" {
		t.Fatalf("scope = %q, want host", resp.Data.Scope)
	}
	// history 改 DATE(collected_at) 按日聚合后,oldTime(2h 前) + newTime(now) 同一天 → 1 个 point
	// 包含全部 6 行(3 process + 3 ports)= Total 6
	if resp.Data.TotalSnapshots != 1 || len(resp.Data.Points) != 1 {
		t.Fatalf("unexpected history points: %+v", resp.Data)
	}
	if resp.Data.Points[0].Total != 6 {
		t.Fatalf("point total = %d, want 6 (3 process + 3 ports same day)", resp.Data.Points[0].Total)
	}
	if resp.Data.LatestCollectedAt == "" {
		t.Fatalf("latest_collected_at should not be empty")
	}
}

func TestAssetRelations(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/relations", handler.GetRelations)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/relations?host_id=host-1", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int                  `json:"code"`
		Data AssetRelationsResult `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0", resp.Code)
	}
	if resp.Data.Scope != "host" {
		t.Fatalf("scope = %q, want host", resp.Data.Scope)
	}
	if resp.Data.HostID != "host-1" {
		t.Fatalf("host_id = %q, want host-1", resp.Data.HostID)
	}
	if resp.Data.Total == 0 || len(resp.Data.Items) == 0 {
		t.Fatalf("relations should not be empty: %+v", resp.Data)
	}

	first := resp.Data.Items[0]
	if first.Process.PID != "101" {
		t.Fatalf("first relation pid = %q, want 101", first.Process.PID)
	}
	if len(first.Ports) == 0 {
		t.Fatalf("expected ports in first relation")
	}
	if len(first.Apps) == 0 {
		t.Fatalf("expected apps in first relation")
	}
	if len(first.Software) == 0 {
		t.Fatalf("expected software in first relation")
	}
	if len(first.Services) == 0 {
		t.Fatalf("expected services in first relation")
	}
	if first.Container == nil || first.Container.ContainerID != "container-1" {
		t.Fatalf("expected container relation, got %+v", first.Container)
	}
	if first.Host.HostID != "host-1" || first.Host.Hostname != "web-01" {
		t.Fatalf("unexpected host info: %+v", first.Host)
	}
	if first.Confidence.Level == "" || len(first.Confidence.MatchedBy) == 0 {
		t.Fatalf("expected confidence info, got %+v", first.Confidence)
	}
	if first.Risks.ExposedPortCount == 0 || first.Risks.VulnerabilityCount == 0 || first.Risks.FIMChangeCount == 0 {
		t.Fatalf("expected risk overlay, got %+v", first.Risks)
	}
	if len(first.Vulnerabilities) == 0 || first.Vulnerabilities[0].CVEID != "CVE-2026-0001" {
		t.Fatalf("expected vulnerability overlay, got %+v", first.Vulnerabilities)
	}
	if len(first.RecentChanges) == 0 || first.RecentChanges[0].EventID != "fim-1" {
		t.Fatalf("expected fim overlay, got %+v", first.RecentChanges)
	}
}

func TestAssetRelationsGlobal(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/relations", handler.GetRelations)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/relations?all=true&keyword=nginx", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int                  `json:"code"`
		Data AssetRelationsResult `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Data.Scope != "global" {
		t.Fatalf("scope = %q, want global", resp.Data.Scope)
	}
	if resp.Data.Total == 0 || len(resp.Data.Items) == 0 {
		t.Fatalf("global relations should not be empty: %+v", resp.Data)
	}
	for _, item := range resp.Data.Items {
		if item.Host.HostID != "host-1" {
			t.Fatalf("global keyword query should only return host-1, got %+v", item.Host)
		}
	}
}

func TestAssetsTopN(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/top", handler.GetTopN)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/top?type=processes&host_id=host-1&limit=3", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int `json:"code"`
		Data struct {
			Items []AssetTopItem `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(resp.Data.Items) == 0 {
		t.Fatalf("top items should not be empty")
	}
	if resp.Data.Items[0].Name != "/usr/bin/nginx" || resp.Data.Items[0].Value != 2 {
		t.Fatalf("unexpected top item: %+v", resp.Data.Items[0])
	}
}

func TestAssetsTopN_PackagesAlias(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/top", handler.GetTopN)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/top?type=packages&host_id=host-1&limit=3", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Code int `json:"code"`
		Data struct {
			Items []AssetTopItem `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(resp.Data.Items) == 0 {
		t.Fatalf("top items should not be empty")
	}
}

func TestAssetSearchFilters(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/processes", handler.ListProcesses)
	r.GET("/ports", handler.ListPorts)

	processResp := httptest.NewRecorder()
	processReq, _ := http.NewRequest(http.MethodGet, "/processes?search=redis", nil)
	r.ServeHTTP(processResp, processReq)

	if processResp.Code != http.StatusOK {
		t.Fatalf("process status = %d, want 200", processResp.Code)
	}

	var listResp struct {
		Code int `json:"code"`
		Data struct {
			Total int64           `json:"total"`
			Items []model.Process `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(processResp.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to unmarshal process response: %v", err)
	}
	if listResp.Data.Total != 1 || len(listResp.Data.Items) != 1 || listResp.Data.Items[0].HostID != "host-2" {
		t.Fatalf("unexpected process search result: %+v", listResp.Data)
	}

	portResp := httptest.NewRecorder()
	portReq, _ := http.NewRequest(http.MethodGet, "/ports?search=6379", nil)
	r.ServeHTTP(portResp, portReq)

	if portResp.Code != http.StatusOK {
		t.Fatalf("port status = %d, want 200", portResp.Code)
	}

	var portListResp struct {
		Code int `json:"code"`
		Data struct {
			Total int64        `json:"total"`
			Items []model.Port `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(portResp.Body.Bytes(), &portListResp); err != nil {
		t.Fatalf("failed to unmarshal port response: %v", err)
	}
	if portListResp.Data.Total != 1 || len(portListResp.Data.Items) != 1 || portListResp.Data.Items[0].Port != 6379 {
		t.Fatalf("unexpected port search result: %+v", portListResp.Data)
	}
}

func TestAssetCollectionStatusMissingCollectorPackage(t *testing.T) {
	handler := seedAssetTestData(t)

	r := gin.New()
	r.GET("/status", handler.GetCollectionStatus)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/status?host_id=host-3", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int                   `json:"code"`
		Data AssetCollectionStatus `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0", resp.Code)
	}
	if resp.Data.HasData {
		t.Fatalf("has_data = true, want false")
	}
	if resp.Data.Collector.PackageUploaded {
		t.Fatalf("package_uploaded = true, want false")
	}
	if resp.Data.Collector.ConfigEnabled {
		t.Fatalf("config_enabled = true, want false")
	}
	if resp.Data.Collector.HostStatus != "not_uploaded" {
		t.Fatalf("host_status = %q, want not_uploaded", resp.Data.Collector.HostStatus)
	}
	if !strings.Contains(resp.Data.Message, "collector") {
		t.Fatalf("message = %q, want mention collector", resp.Data.Message)
	}
}

func TestAssetCollectionStatusRunningCollector(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)

	now := model.LocalTime(time.Now())
	pkgDir := t.TempDir()
	pkgPath := filepath.Join(pkgDir, "collector_amd64")
	if err := os.WriteFile(pkgPath, []byte("collector"), 0o644); err != nil {
		t.Fatalf("failed to write collector package: %v", err)
	}

	component := &model.Component{Name: "collector", Category: model.ComponentCategoryPlugin, Description: "collector"}
	if err := db.Create(component).Error; err != nil {
		t.Fatalf("failed to create component: %v", err)
	}

	version := &model.ComponentVersion{ComponentID: component.ID, Version: "1.2.3", IsLatest: true}
	if err := db.Create(version).Error; err != nil {
		t.Fatalf("failed to create component version: %v", err)
	}

	pkg := &model.ComponentPackage{
		VersionID: version.ID,
		OS:        "linux",
		Arch:      "amd64",
		PkgType:   model.PackageTypeBinary,
		FilePath:  pkgPath,
		FileName:  "collector_amd64",
		FileSize:  9,
		SHA256:    "abc",
		Enabled:   true,
	}
	if err := db.Create(pkg).Error; err != nil {
		t.Fatalf("failed to create component package: %v", err)
	}

	pluginConfig := &model.PluginConfig{
		Name:         "collector",
		Type:         model.PluginTypeCollector,
		Version:      "1.2.3",
		SHA256:       "abc",
		DownloadURLs: model.StringArray{"/api/v1/plugins/download/collector"},
		RuntimeTypes: model.StringArray{"vm"},
		Enabled:      true,
	}
	if err := db.Create(pluginConfig).Error; err != nil {
		t.Fatalf("failed to create plugin config: %v", err)
	}

	hostPlugin := &model.HostPlugin{
		HostID:    "host-1",
		Name:      "collector",
		Version:   "1.2.3",
		Status:    model.HostPluginStatusRunning,
		UpdatedAt: now,
	}
	if err := db.Create(hostPlugin).Error; err != nil {
		t.Fatalf("failed to create host plugin: %v", err)
	}

	process := &model.Process{
		ID:          "proc-running",
		HostID:      "host-1",
		PID:         "321",
		PPID:        "1",
		Exe:         "/usr/bin/bash",
		Cmdline:     "bash",
		Username:    "root",
		CollectedAt: now,
	}
	if err := db.Create(process).Error; err != nil {
		t.Fatalf("failed to create process: %v", err)
	}

	handler := NewAssetsHandler(db, zap.NewNop())
	r := gin.New()
	r.GET("/status", handler.GetCollectionStatus)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/status?host_id=host-1", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code int                   `json:"code"`
		Data AssetCollectionStatus `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !resp.Data.HasData {
		t.Fatalf("has_data = false, want true")
	}
	if !resp.Data.Collector.PackageUploaded {
		t.Fatalf("package_uploaded = false, want true")
	}
	if !resp.Data.Collector.ConfigEnabled {
		t.Fatalf("config_enabled = false, want true")
	}
	if resp.Data.Collector.HostStatus != "running" {
		t.Fatalf("host_status = %q, want running", resp.Data.Collector.HostStatus)
	}
	if resp.Data.Message != "" {
		t.Fatalf("message = %q, want empty", resp.Data.Message)
	}
}
