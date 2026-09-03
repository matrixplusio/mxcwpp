package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRockyFetch_TrailingSlash 锁定 apollo 尾斜杠修复：
// /advisories(无斜杠)会 307 跳到 http:// 降级地址,部分 client 不跟随 → 拉空。
// fetcher 必须直接请求 /advisories/(带斜杠)避开。
// 若有人去掉斜杠,mock 的无斜杠路径会 307 到坏地址 → Fetch 拿不到数据 → 测试失败。
func TestRockyFetch_TrailingSlash(t *testing.T) {
	body := rockyResp{
		Advisories: []rockyAdvisory{{
			ID:          9153,
			Name:        "RLSA-2023:2589",
			Kind:        "Security",
			Severity:    "Moderate",
			Synopsis:    "Moderate: autotrace security update",
			PublishedAt: time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339),
			AffectedProducts: []rockyAffectedProduct{
				{Variant: "Rocky Linux", Name: "Rocky Linux 9 x86_64", MajorVersion: 9, Arch: "x86_64"},
			},
			CVEs:     []rockyCVE{{CVE: "CVE-2022-32323", CVSS3Score: "7.3"}},
			Packages: []rockyPackage{{NEVRA: "autotrace-0:0.31.1-65.el9.x86_64", Checksum: "abc", ChecksumType: "sha256"}},
		}},
		Page: 1, Size: 100, Total: 1,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟真实 apollo：无尾斜杠 → 307 跳到坏地址（不跟随=拉空）。
		if strings.HasSuffix(r.URL.Path, "/advisories") {
			http.Redirect(w, r, "/dead-end", http.StatusTemporaryRedirect)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/advisories/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := NewRockySource().WithBaseURL(srv.URL + "/api/v3").WithHTTPClient(srv.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	advs, err := r.Fetch(ctx, time.Time{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1 (尾斜杠修复回归)", len(advs))
	}
	a := advs[0]
	if a.AdvisoryID != "RLSA-2023:2589" {
		t.Errorf("advisory_id=%q", a.AdvisoryID)
	}
	if len(a.AffectedPkgs) == 0 {
		t.Errorf("AffectedPkgs 为空,匹配会失败")
	}
	if len(a.AffectedPkgs) > 0 && a.AffectedPkgs[0].FixedVersion == "" {
		t.Errorf("FixedVersion 为空,匹配会失败")
	}
}
