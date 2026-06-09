package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	d := NewNVDDriver("", "", 0)
	if err := r.Register(d); err != nil {
		t.Fatalf("register: %v", err)
	}
	got, ok := r.Get("nvd")
	if !ok {
		t.Fatal("expected nvd in registry")
	}
	if got.Name() != "nvd" {
		t.Errorf("expected nvd, got %s", got.Name())
	}
}

func TestRegistry_RejectDuplicate(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_ = r.Register(NewNVDDriver("", "", 0))
	if err := r.Register(NewNVDDriver("", "", 0)); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestRegistry_RejectNil(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Fatal("expected nil error")
	}
}

func TestNVDDriver_Fetch_MockServer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"vulnerabilities": []map[string]any{
				{
					"cve": map[string]any{
						"id":           "CVE-2024-9999",
						"published":    "2024-01-01T00:00:00.000",
						"lastModified": "2024-01-02T00:00:00.000",
						"descriptions": []map[string]string{{"lang": "en", "value": "test desc"}},
						"metrics": map[string]any{
							"cvssMetricV31": []map[string]any{
								{
									"cvssData": map[string]any{
										"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										"baseScore":    9.8,
										"baseSeverity": "CRITICAL",
									},
								},
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	d := NewNVDDriver(srv.URL, "", time.Second*5)
	res, err := d.Fetch(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(res.Advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(res.Advisories))
	}
	a := res.Advisories[0]
	if a.CVE != "CVE-2024-9999" {
		t.Errorf("cve: got %s", a.CVE)
	}
	if a.Severity != "critical" {
		t.Errorf("severity: got %s", a.Severity)
	}
	if a.CVSSv3Score != 9.8 {
		t.Errorf("score: got %v", a.CVSSv3Score)
	}
}

func TestCISAKEVDriver_Fetch_MockServer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"vulnerabilities": []map[string]any{
				{
					"cveID":             "CVE-2024-1111",
					"vendorProject":     "TestVendor",
					"product":           "TestProduct",
					"vulnerabilityName": "Test KEV Entry",
					"dateAdded":         "2024-01-01",
					"shortDescription":  "test kev",
					"requiredAction":    "patch immediately",
					"dueDate":           "2024-02-01",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	d := &CISAKEVDriver{URL: srv.URL, Client: &http.Client{Timeout: 5 * time.Second}}
	res, err := d.Fetch(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(res.Advisories) != 1 {
		t.Fatalf("expected 1, got %d", len(res.Advisories))
	}
	a := res.Advisories[0]
	if !a.KEVKnown {
		t.Error("expected KEVKnown=true")
	}
	if a.CVE != "CVE-2024-1111" {
		t.Errorf("cve: got %s", a.CVE)
	}
}
