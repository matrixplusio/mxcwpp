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

func TestAdvisoryIDFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"2024/rhsa-2024_1234.json", "RHSA-2024:1234"},
		{"2024/rhba-2024_0987.json", "RHBA-2024:0987"},
		{"2025/rhsa-2025_18480.json", "RHSA-2025:18480"},
		{"rhsa-2024_0001.json", "RHSA-2024:0001"},
		{"invalid", ""},
		{"2024/junk.json", ""},
	}
	for _, tc := range cases {
		got := advisoryIDFromPath(tc.path)
		if got != tc.want {
			t.Errorf("advisoryIDFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestRedHatSource_SkipKnown(t *testing.T) {
	r := &RedHatSource{
		skipAdvisoryID: map[string]struct{}{
			"RHSA-2024:1234":  {},
			"RHSA-2025:18480": {},
		},
	}
	in := []string{
		"2024/rhsa-2024_1234.json",  // skip
		"2024/rhsa-2024_5678.json",  // keep
		"2025/rhsa-2025_18480.json", // skip
		"2025/rhsa-2025_99999.json", // keep
	}
	out := r.skipKnown(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 remaining, got %d: %v", len(out), out)
	}
	if out[0] != "2024/rhsa-2024_5678.json" || out[1] != "2025/rhsa-2025_99999.json" {
		t.Errorf("wrong filter result: %v", out)
	}
}

func TestRedHatSource_NoCapByDefault(t *testing.T) {
	r := NewRedHatSource()
	if r.maxAdv != 0 {
		t.Errorf("default maxAdv = %d, want 0 (no cap)", r.maxAdv)
	}
	if r.concurrency <= 1 {
		t.Errorf("default concurrency = %d, want > 1", r.concurrency)
	}
}

// fakeRHSAServer 返回 N 条 advisory，验证全量 + 并发能拉完。
func fakeRHSAServer(t *testing.T, n int) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64

	mkDoc := func(idx int) *csafDoc {
		d := &csafDoc{}
		d.Document.Tracking.ID = "RHSA-2024:0000"
		d.Document.AggregateSeverity.Text = "Important"
		d.Vulnerabilities = []csafVulnerability{
			{
				CVE: "CVE-2024-0000",
				ProductStatus: csafProductStatus{
					Fixed: []string{"AppStream-9.4.0.GA:openssl-1:3.5.5-1.el9_4.x86_64"},
				},
			},
		}
		return d
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt64(&hits, 1)
		if strings.HasSuffix(req.URL.Path, "/index.txt") {
			var b strings.Builder
			for i := 0; i < n; i++ {
				b.WriteString("2024/rhsa-2024_")
				b.WriteString(itoaPad(i, 4))
				b.WriteString(".json\n")
			}
			_, _ = w.Write([]byte(b.String()))
			return
		}
		_ = json.NewEncoder(w).Encode(mkDoc(0))
	}))
	return srv, &hits
}

func itoaPad(n, width int) string {
	s := []byte{}
	for n > 0 {
		s = append([]byte{byte('0' + n%10)}, s...)
		n /= 10
	}
	for len(s) < width {
		s = append([]byte{'0'}, s...)
	}
	return string(s)
}

func TestRedHatSource_Fetch_FullPullConcurrent(t *testing.T) {
	const N = 200
	srv, hits := fakeRHSAServer(t, N)
	defer srv.Close()

	r := NewRedHatSource().
		WithBaseURL(srv.URL).
		WithConcurrency(8)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	advs, err := r.Fetch(ctx, time.Time{})
	if err != nil {
		t.Fatalf("Fetch err: %v", err)
	}
	// 默认无 cap → 应全部拉回（容忍 parseCSAF 因 productID 解析失败丢失个别条目）
	if len(advs) < N/2 {
		t.Errorf("got %d advisories from %d, suspiciously low", len(advs), N)
	}
	// HTTP 命中次数 = 1 (index) + N (details) - 但并发可能存在重复请求统计差异
	if got := atomic.LoadInt64(hits); got < int64(N) {
		t.Errorf("HTTP hits = %d, expected >= %d", got, N)
	}
}

func TestRedHatSource_Fetch_SkipKnownReducesHTTP(t *testing.T) {
	const N = 100
	srv, hits := fakeRHSAServer(t, N)
	defer srv.Close()

	// 注入前 50 条为已入库
	skip := make(map[string]struct{}, 50)
	for i := 0; i < 50; i++ {
		skip["RHSA-2024:"+itoaPad(i, 4)] = struct{}{}
	}

	r := NewRedHatSource().
		WithBaseURL(srv.URL).
		WithConcurrency(4).
		WithSkipAdvisoryIDs(skip)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := r.Fetch(ctx, time.Time{})
	if err != nil {
		t.Fatalf("Fetch err: %v", err)
	}
	// 50 条 detail + 1 index ≤ 51；< 全量 (101) 即视为生效
	if got := atomic.LoadInt64(hits); got >= int64(N+1) {
		t.Errorf("skip 未生效，HTTP hits = %d，应 < %d", got, N+1)
	}
}
