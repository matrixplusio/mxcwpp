package advisory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newUSNSchema 是 ubuntu.com USN list API 的当前 schema 样本 (2026 起):
// cves_ids 扁平数组、release_packages 携带包修复、releases 仅元数据。
const newUSNSchema = `{
  "notices": [
    {
      "id": "USN-8472-1",
      "title": "containerd vulnerabilities",
      "type": "USN",
      "published": "2026-06-25T13:18:21.382313",
      "summary": "Several security issues were fixed in containerd.",
      "cves_ids": ["CVE-2026-53492", "CVE-2026-53489"],
      "references": [],
      "releases": [
        {"codename": "resolute", "version": "26.04"},
        {"codename": "focal", "version": "20.04"}
      ],
      "release_packages": {
        "focal": [
          {"name": "containerd-app", "version": "1.7.24-0ubuntu1~20.04.2+esm2"}
        ],
        "resolute": [
          {"name": "containerd", "version": "1.7.27-0ubuntu1"}
        ]
      }
    }
  ],
  "total_results": 1
}`

// TestUbuntuFetch_NewSchema 回归: 对当前 USN schema (cves_ids / release_packages /
// releases 列表) 正确解析出 advisory。防止上游契约再次静默变更时无声同步 0 条。
func TestUbuntuFetch_NewSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(newUSNSchema))
	}))
	defer srv.Close()

	src := NewUbuntuSource().WithBaseURL(srv.URL).WithHTTPClient(srv.Client())
	advs, err := src.Fetch(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// 一条 notice × 两个 release(focal/resolute) → 2 条 advisory
	if len(advs) != 2 {
		t.Fatalf("advisory count = %d, want 2: %+v", len(advs), advs)
	}

	byID := map[string]*Advisory{}
	for _, a := range advs {
		byID[a.AdvisoryID] = a
	}

	focal := byID["USN-8472-1/focal"]
	if focal == nil {
		t.Fatalf("missing advisory USN-8472-1/focal: %+v", byID)
	}
	if focal.OSMajorVer != "20.04" {
		t.Errorf("focal OSMajorVer = %q, want 20.04", focal.OSMajorVer)
	}
	if len(focal.CVEIDs) != 2 || focal.CVEIDs[0] != "CVE-2026-53492" {
		t.Errorf("focal CVEIDs = %v, want [CVE-2026-53492 CVE-2026-53489]", focal.CVEIDs)
	}
	if len(focal.AffectedPkgs) != 1 || focal.AffectedPkgs[0].Name != "containerd-app" ||
		focal.AffectedPkgs[0].FixedVersion != "1.7.24-0ubuntu1~20.04.2+esm2" {
		t.Errorf("focal AffectedPkgs = %+v, want containerd-app@1.7.24-...", focal.AffectedPkgs)
	}

	// resolute 不在静态 codename 表里，版本号应回退取自 releases 元数据。
	if res := byID["USN-8472-1/resolute"]; res == nil || res.OSMajorVer != "26.04" {
		t.Errorf("resolute advisory wrong: %+v", res)
	}
}

// TestUbuntuFetch_Non200 回归: 非 200 (如 422/504) 必须短路成清晰错误,
// 而不是把 HTML 当 JSON 解码得到 "invalid character '<'"。
func TestUbuntuFetch_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity) // 422
		_, _ = w.Write([]byte("<!DOCTYPE html><html>error</html>"))
	}))
	defer srv.Close()

	src := NewUbuntuSource().WithBaseURL(srv.URL).WithHTTPClient(srv.Client())
	_, err := src.Fetch(context.Background(), time.Time{})
	if err == nil {
		t.Fatalf("expected error on 422, got nil")
	}
}
