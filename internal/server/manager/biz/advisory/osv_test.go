package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mockOSVServer 模拟 osv.dev 上游：/v1/querybatch + /v1/vulns/{id}。
type mockOSVServer struct {
	*httptest.Server
	batchHits  atomic.Int32
	detailHits atomic.Int32
	// purl -> [vuln IDs]
	purlVulns map[string][]string
	// vuln ID -> raw detail JSON
	details map[string]string
}

func newMockOSVServer(purlVulns map[string][]string, details map[string]string) *mockOSVServer {
	m := &mockOSVServer{purlVulns: purlVulns, details: details}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		m.batchHits.Add(1)
		var req struct {
			Queries []struct {
				Package struct {
					PURL string `json:"purl"`
				} `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		type vEntry struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		}
		type result struct {
			Vulns []vEntry `json:"vulns,omitempty"`
		}
		resp := struct {
			Results []result `json:"results"`
		}{}
		for _, q := range req.Queries {
			ids := m.purlVulns[q.Package.PURL]
			r := result{}
			for _, id := range ids {
				r.Vulns = append(r.Vulns, vEntry{ID: id, Modified: "2024-01-01T00:00:00Z"})
			}
			resp.Results = append(resp.Results, r)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		m.detailHits.Add(1)
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		raw, ok := m.details[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(raw))
	})
	m.Server = httptest.NewServer(mux)
	return m
}

func TestOSVSource_FetchByPURLs_BasicMavenHit(t *testing.T) {
	const purl = "pkg:maven/io.netty/netty-codec@4.1.115.Final"
	purlVulns := map[string][]string{purl: {"GHSA-xxx-yyy-zzz"}}
	details := map[string]string{
		"GHSA-xxx-yyy-zzz": `{
            "id":"GHSA-xxx-yyy-zzz",
            "summary":"Netty HTTP request smuggling",
            "details":"Long details",
            "aliases":["CVE-2026-42583"],
            "modified":"2026-05-01T00:00:00Z",
            "published":"2026-04-01T00:00:00Z",
            "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected":[{
                "package":{"ecosystem":"Maven","name":"io.netty:netty-codec"},
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.1.133.Final"}]}]
            }],
            "references":[{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-xxx-yyy-zzz"}]
        }`,
	}
	srv := newMockOSVServer(purlVulns, details)
	defer srv.Close()

	src := NewOSVSource().WithBaseURL(srv.URL)
	out, err := src.FetchByPURLs(context.Background(), []string{purl})
	if err != nil {
		t.Fatalf("FetchByPURLs err: %v", err)
	}
	advs, ok := out[purl]
	if !ok || len(advs) != 1 {
		t.Fatalf("expect 1 advisory for purl, got %d (out=%+v)", len(advs), out)
	}
	a := advs[0]
	if a.OsvID != "GHSA-xxx-yyy-zzz" {
		t.Errorf("OsvID=%q", a.OsvID)
	}
	if len(a.CVEIDs) != 1 || a.CVEIDs[0] != "CVE-2026-42583" {
		t.Errorf("CVEIDs=%v", a.CVEIDs)
	}
	if a.PURL != purl {
		t.Errorf("PURL=%q", a.PURL)
	}
	if a.Ecosystem != "Maven" {
		t.Errorf("Ecosystem=%q", a.Ecosystem)
	}
	if a.CVSSScore < 9.0 {
		t.Errorf("CVSSScore=%v (expect critical 9+)", a.CVSSScore)
	}
	if a.Severity != SeverityCritical {
		t.Errorf("Severity=%q", a.Severity)
	}
	if a.AttackVector != "network" {
		t.Errorf("AttackVector=%q", a.AttackVector)
	}
	if a.CurrentVersion != "4.1.115.Final" {
		t.Errorf("CurrentVersion=%q", a.CurrentVersion)
	}
	if len(a.AffectedPkgs) != 1 || a.AffectedPkgs[0].FixedVersion != "4.1.133.Final" {
		t.Errorf("AffectedPkgs=%+v", a.AffectedPkgs)
	}
	if a.AffectedVersions != "< 4.1.133.Final" && a.AffectedVersions != ">= 0, < 4.1.133.Final" {
		t.Errorf("AffectedVersions=%q", a.AffectedVersions)
	}
	if srv.batchHits.Load() != 1 {
		t.Errorf("batchHits=%d", srv.batchHits.Load())
	}
	if srv.detailHits.Load() != 1 {
		t.Errorf("detailHits=%d", srv.detailHits.Load())
	}
}

func TestOSVSource_FetchByPURLs_SkipOSSFuzz(t *testing.T) {
	const purl = "pkg:golang/example.com%2Fpkg@v1.0.0"
	// 同时返回 OSV-2024-1 (OSS-Fuzz crash) 与 GHSA-zzz
	purlVulns := map[string][]string{purl: {"OSV-2024-1", "GHSA-zzz"}}
	details := map[string]string{
		"GHSA-zzz": `{"id":"GHSA-zzz","summary":"x","aliases":["CVE-2026-1111"],"affected":[{"package":{"ecosystem":"Go","name":"example.com/pkg"},"ranges":[{"events":[{"fixed":"v1.1.0"}]}]}]}`,
	}
	srv := newMockOSVServer(purlVulns, details)
	defer srv.Close()

	src := NewOSVSource().WithBaseURL(srv.URL)
	out, err := src.FetchByPURLs(context.Background(), []string{purl})
	if err != nil {
		t.Fatalf("FetchByPURLs err: %v", err)
	}
	if len(out[purl]) != 1 {
		t.Fatalf("expect 1 advisory (OSS-Fuzz 应被过滤), got %d", len(out[purl]))
	}
	if out[purl][0].OsvID != "GHSA-zzz" {
		t.Errorf("OsvID=%q", out[purl][0].OsvID)
	}
	// OSV-2024-1 不应触发 detail fetch
	if srv.detailHits.Load() != 1 {
		t.Errorf("detailHits=%d (期望仅 1 次)", srv.detailHits.Load())
	}
}

func TestOSVSource_FetchByPURLs_KnownIDsSkipDetail(t *testing.T) {
	const purl = "pkg:npm/safe-regex@1.1.0"
	purlVulns := map[string][]string{purl: {"GHSA-known", "GHSA-new"}}
	details := map[string]string{
		"GHSA-new": `{"id":"GHSA-new","summary":"new","aliases":["CVE-2026-2222"],"affected":[{"package":{"ecosystem":"npm","name":"safe-regex"},"ranges":[{"events":[{"fixed":"2.0.0"}]}]}]}`,
	}
	srv := newMockOSVServer(purlVulns, details)
	defer srv.Close()

	src := NewOSVSource().
		WithBaseURL(srv.URL).
		WithKnownVulnIDs(map[string]struct{}{"GHSA-known": {}})

	out, err := src.FetchByPURLs(context.Background(), []string{purl})
	if err != nil {
		t.Fatalf("FetchByPURLs err: %v", err)
	}
	if len(out[purl]) != 2 {
		t.Fatalf("expect 2 advisories (1 minimal + 1 detailed), got %d", len(out[purl]))
	}
	if srv.detailHits.Load() != 1 {
		t.Errorf("detailHits=%d (期望 1，known ID 应跳过)", srv.detailHits.Load())
	}
	// 找到 minimal 的 known + 新的
	var known, new1 *Advisory
	for _, a := range out[purl] {
		switch a.OsvID {
		case "GHSA-known":
			known = a
		case "GHSA-new":
			new1 = a
		}
	}
	if known == nil || new1 == nil {
		t.Fatalf("missing known/new advisory; out=%+v", out)
	}
	if len(known.CVEIDs) != 0 {
		t.Errorf("known advisory should be minimal (no CVE list), got %v", known.CVEIDs)
	}
	if new1.OsvID != "GHSA-new" || len(new1.CVEIDs) == 0 {
		t.Errorf("new advisory invalid: %+v", new1)
	}
}

// stubDetailCache 仅实现 advisory.DetailCache 给单测用。
type stubDetailCache struct {
	store map[string][]byte
}

func (s *stubDetailCache) Get(id string) ([]byte, bool) {
	v, ok := s.store[id]
	return v, ok
}
func (s *stubDetailCache) GetIncludeExpired(id string) ([]byte, bool) {
	v, ok := s.store[id]
	return v, ok
}
func (s *stubDetailCache) Put(id string, raw []byte) {
	if s.store == nil {
		s.store = make(map[string][]byte)
	}
	s.store[id] = raw
}

func TestOSVSource_CacheStrategy_PreferOnline_FillsCache(t *testing.T) {
	const purl = "pkg:pypi/requests@2.20.0"
	purlVulns := map[string][]string{purl: {"GHSA-abc"}}
	details := map[string]string{
		"GHSA-abc": `{"id":"GHSA-abc","summary":"x","aliases":["CVE-2026-3333"],"affected":[{"package":{"ecosystem":"PyPI","name":"requests"},"ranges":[{"events":[{"fixed":"2.32.0"}]}]}]}`,
	}
	srv := newMockOSVServer(purlVulns, details)
	defer srv.Close()

	cache := &stubDetailCache{}
	src := NewOSVSource().WithBaseURL(srv.URL).WithCache(cache, CacheStrategyPreferOnline)
	if _, err := src.FetchByPURLs(context.Background(), []string{purl}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if _, ok := cache.store["GHSA-abc"]; !ok {
		t.Errorf("cache 未写入 GHSA-abc")
	}
}

func TestOSVSource_PURLEcosystem_MavenSplit(t *testing.T) {
	// purlPkgName 对 maven 类型应拆 group/artifact → group:artifact 形式
	cases := []struct {
		purl    string
		wantPkg string
		wantEco string
	}{
		{"pkg:maven/io.netty/netty-codec@4.1.115.Final", "io.netty:netty-codec", "Maven"},
		{"pkg:npm/safe-regex@1.1.0", "safe-regex", "npm"},
		{"pkg:pypi/requests@2.20.0", "requests", "PyPI"},
		{"pkg:golang/go.uber.org%2Fzap@v1.27.1", "go.uber.org%2Fzap", "Go"},
	}
	for _, c := range cases {
		if got := purlPkgName(c.purl); got != c.wantPkg {
			t.Errorf("purlPkgName(%s)=%q want %q", c.purl, got, c.wantPkg)
		}
		if got := purlEcosystem(c.purl); got != c.wantEco {
			t.Errorf("purlEcosystem(%s)=%q want %q", c.purl, got, c.wantEco)
		}
	}
}

func TestOSVSource_FilterOSVPURLs(t *testing.T) {
	in := []string{
		"pkg:maven/io.netty/netty-codec@4.1.115.Final",
		"pkg:rpm/redhat/openssl@3.5.1",
		"pkg:npm/lodash@4.17.20",
		"pkg:deb/debian/curl@7.74.0",
	}
	want := []string{
		"pkg:maven/io.netty/netty-codec@4.1.115.Final",
		"pkg:npm/lodash@4.17.20",
	}
	got := FilterOSVPURLs(in)
	if len(got) != len(want) {
		t.Fatalf("len mismatch: got %d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func TestOSVSource_Fetch_AlwaysEmpty(t *testing.T) {
	// time-incremental Fetch 在 OSVSource 应返回 nil（PURL 模式入口走 FetchByPURLs）
	src := NewOSVSource()
	advs, err := src.Fetch(context.Background(), time.Time{})
	if err != nil || advs != nil {
		t.Errorf("Fetch should be nil,nil got advs=%v err=%v", advs, err)
	}
}
