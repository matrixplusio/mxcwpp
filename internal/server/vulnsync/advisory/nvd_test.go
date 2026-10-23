package advisory

import (
	"testing"
)

func TestParseNVD2Response_v31(t *testing.T) {
	body := []byte(`{
		"vulnerabilities": [{
			"cve": {
				"id": "CVE-2024-12345",
				"published": "2024-05-01T10:00:00.000",
				"lastModified": "2024-05-15T12:30:00.000",
				"descriptions": [
					{"lang": "zh", "value": "中文描述跳过"},
					{"lang": "en", "value": "Buffer overflow in foo allows RCE."}
				],
				"metrics": {
					"cvssMetricV31": [{
						"cvssData": {
							"baseScore": 9.8,
							"baseSeverity": "CRITICAL",
							"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
						}
					}]
				}
			}
		}]
	}`)
	res, err := parseNVD2Response("CVE-2024-12345", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res == nil {
		t.Fatal("got nil")
	}
	if res.CVSSScore != 9.8 {
		t.Errorf("score=%v want 9.8", res.CVSSScore)
	}
	if res.Severity != "critical" {
		t.Errorf("severity=%q want critical", res.Severity)
	}
	if res.Description != "Buffer overflow in foo allows RCE." {
		t.Errorf("desc=%q", res.Description)
	}
	if res.CVSSVector == "" {
		t.Error("vector empty")
	}
}

func TestParseNVD2Response_v30Fallback(t *testing.T) {
	body := []byte(`{
		"vulnerabilities": [{
			"cve": {
				"id": "CVE-2018-0001",
				"descriptions": [{"lang": "en", "value": "Old CVE"}],
				"metrics": {
					"cvssMetricV30": [{
						"cvssData": {
							"baseScore": 7.5,
							"baseSeverity": "HIGH",
							"vectorString": "CVSS:3.0/..."
						}
					}]
				}
			}
		}]
	}`)
	res, err := parseNVD2Response("CVE-2018-0001", body)
	if err != nil || res == nil {
		t.Fatalf("parse: %v / nil=%v", err, res == nil)
	}
	if res.CVSSScore != 7.5 || res.Severity != "high" {
		t.Errorf("got score=%v severity=%q", res.CVSSScore, res.Severity)
	}
}

func TestParseNVD2Response_NoCVSS(t *testing.T) {
	body := []byte(`{
		"vulnerabilities": [{
			"cve": {
				"id": "CVE-2024-00000",
				"descriptions": [{"lang": "en", "value": "Reserved CVE"}],
				"metrics": {}
			}
		}]
	}`)
	res, err := parseNVD2Response("CVE-2024-00000", body)
	if err != nil || res == nil {
		t.Fatalf("parse: %v / nil=%v", err, res == nil)
	}
	if res.CVSSScore != 0 {
		t.Errorf("expected 0 score for no-CVSS CVE, got %v", res.CVSSScore)
	}
	if res.Description != "Reserved CVE" {
		t.Errorf("desc=%q", res.Description)
	}
}

func TestParseNVD2Response_Empty(t *testing.T) {
	body := []byte(`{"vulnerabilities": []}`)
	res, err := parseNVD2Response("CVE-NOT-EXISTS", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res != nil {
		t.Errorf("expected nil for empty response, got %+v", res)
	}
}

func TestNVDClient_Interval(t *testing.T) {
	// 无 API key → 6s 间隔
	c := NewNVDClient("", nil)
	if c.interval != nvdRateNoAPIKey {
		t.Errorf("no-key interval=%v want %v", c.interval, nvdRateNoAPIKey)
	}
	// 有 key → 0.6s
	c2 := NewNVDClient("test-key", nil)
	if c2.interval != nvdRateWithKey {
		t.Errorf("with-key interval=%v want %v", c2.interval, nvdRateWithKey)
	}
}
