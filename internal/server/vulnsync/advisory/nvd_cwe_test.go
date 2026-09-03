package advisory

import (
	"strings"
	"testing"
)

func TestParseNVD2Response_CWE(t *testing.T) {
	body := []byte(`{
		"vulnerabilities":[{"cve":{
			"id":"CVE-2024-12345",
			"descriptions":[{"lang":"en","value":"RCE bug"}],
			"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"v1"}}]},
			"weaknesses":[
				{"source":"nvd@nist.gov","type":"Primary","description":[{"lang":"en","value":"CWE-78"}]},
				{"source":"secondary","type":"Secondary","description":[{"lang":"en","value":"CWE-200"}]},
				{"source":"x","type":"Primary","description":[{"lang":"zh","value":"中文CWE-22"}]}
			]
		}}]
	}`)
	res, err := parseNVD2Response("CVE-2024-12345", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res == nil {
		t.Fatal("nil")
	}
	if !strings.Contains(res.CWEIDs, "CWE-78") || !strings.Contains(res.CWEIDs, "CWE-200") {
		t.Errorf("expected CWE-78 + CWE-200 in %q", res.CWEIDs)
	}
	// 中文 lang 应被跳过
	if strings.Contains(res.CWEIDs, "CWE-22") {
		t.Error("中文 lang 不应解析")
	}
	// 含 RCE 类(CWE-78=OS Command Injection)→ rce 分类
	if res.CWECategory != "rce" {
		t.Errorf("expected rce got %q", res.CWECategory)
	}
}

func TestMapCWECategory(t *testing.T) {
	cases := []struct {
		name string
		cwes []string
		want string
	}{
		{"rce CWE-94", []string{"CWE-94"}, "rce"},
		{"rce CWE-78 cmd inject", []string{"CWE-78"}, "rce"},
		{"privesc CWE-269", []string{"CWE-269"}, "privesc"},
		{"sqli CWE-89", []string{"CWE-89"}, "sqli"},
		{"path traversal CWE-22", []string{"CWE-22"}, "path_traversal"},
		{"xss CWE-79", []string{"CWE-79"}, "xss"},
		{"info disclosure CWE-200", []string{"CWE-200"}, "info_disclosure"},
		{"dos CWE-400", []string{"CWE-400"}, "dos"},
		// 多 CWE 优先级 (rce 应胜过 info_disclosure)
		{"mixed rce>info", []string{"CWE-200", "CWE-78"}, "rce"},
		// 未知
		{"unknown only", []string{"CWE-9999"}, "other"},
		{"empty", []string{}, "other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mapCWECategory(c.cwes)
			if got != c.want {
				t.Errorf("mapCWECategory(%v) = %q want %q", c.cwes, got, c.want)
			}
		})
	}
}
