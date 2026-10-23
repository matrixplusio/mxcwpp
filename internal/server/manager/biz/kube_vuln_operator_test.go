package biz

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func newTestOperator() *KubeVulnOperator {
	return &KubeVulnOperator{}
}

func TestRenderObjects_ParsesAllDocs(t *testing.T) {
	o := newTestOperator()
	objs, err := o.renderObjects("", "")
	if err != nil {
		t.Fatalf("renderObjects 失败: %v", err)
	}
	if len(objs) < 20 {
		t.Fatalf("期望解析出 >=20 个对象，实际 %d", len(objs))
	}
	// 排序后第一个应为 Namespace（确保 namespaced 资源有归属）
	if objs[0].GetKind() != "Namespace" {
		t.Errorf("期望首个对象为 Namespace，实际 %s", objs[0].GetKind())
	}
	// CRD 必须存在
	var hasCRD, hasDeploy bool
	for _, obj := range objs {
		switch obj.GetKind() {
		case "CustomResourceDefinition":
			hasCRD = true
		case "Deployment":
			hasDeploy = true
		}
	}
	if !hasCRD {
		t.Error("manifest 缺少 CustomResourceDefinition")
	}
	if !hasDeploy {
		t.Error("manifest 缺少 Deployment")
	}
}

func TestRenderObjects_ImageRewrite(t *testing.T) {
	o := newTestOperator()
	const reg = "registry.internal.local"
	objs, err := o.renderObjects(reg, "")
	if err != nil {
		t.Fatalf("renderObjects 失败: %v", err)
	}
	for _, obj := range objs {
		if obj.GetKind() != "Deployment" {
			continue
		}
		containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		for _, c := range containers {
			cm := c.(map[string]any)
			img, _ := cm["image"].(string)
			if strings.Contains(img, "ghcr.io/aquasecurity") {
				t.Errorf("镜像未重写: %s", img)
			}
			if img != "" && !strings.HasPrefix(img, reg) {
				t.Errorf("镜像前缀未指向私有 registry: %s", img)
			}
		}
	}
}

func TestRenderObjects_WebhookInjection(t *testing.T) {
	o := newTestOperator()
	const url = "https://mgr.example.com/api/v1/kube/scanner/report-webhook/tok123"
	objs, err := o.renderObjects("", url)
	if err != nil {
		t.Fatalf("renderObjects 失败: %v", err)
	}
	var found bool
	for _, obj := range objs {
		if obj.GetKind() != "Deployment" || obj.GetName() != trivyOperatorDeployment {
			continue
		}
		containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		env, _, _ := unstructured.NestedSlice(containers[0].(map[string]any), "env")
		for _, e := range env {
			em := e.(map[string]any)
			if em["name"] == "OPERATOR_WEBHOOK_BROADCAST_URL" && em["value"] == url {
				found = true
			}
		}
	}
	if !found {
		t.Error("operator Deployment 未注入 OPERATOR_WEBHOOK_BROADCAST_URL")
	}
}

func TestParseVulnReport(t *testing.T) {
	report := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"report": map[string]any{
			"artifact": map[string]any{
				"repository": "library/nginx",
				"tag":        "1.25",
				"digest":     "sha256:abc",
			},
			"registry": map[string]any{"server": "index.docker.io"},
			"os":       map[string]any{"family": "debian", "name": "12"},
			"summary": map[string]any{
				"criticalCount": int64(2),
				"highCount":     int64(3),
			},
			"vulnerabilities": []any{
				map[string]any{"vulnerabilityID": "CVE-1", "resource": "openssl", "installedVersion": "1.0", "fixedVersion": "1.1", "severity": "CRITICAL", "title": "x"},
				map[string]any{"vulnerabilityID": "CVE-2", "resource": "zlib", "severity": "HIGH"},
				// 重复项应去重
				map[string]any{"vulnerabilityID": "CVE-1", "resource": "openssl", "severity": "CRITICAL"},
			},
		},
	}}

	scan, vulns := parseVulnReport(7, report)
	if scan == nil {
		t.Fatal("解析返回 nil")
	}
	if scan.Image != "index.docker.io/library/nginx:1.25" {
		t.Errorf("镜像名错误: %s", scan.Image)
	}
	if scan.ClusterID == nil || *scan.ClusterID != 7 {
		t.Error("ClusterID 未正确填充")
	}
	if scan.Source != "cluster" {
		t.Errorf("Source 错误: %s", scan.Source)
	}
	if scan.CriticalCnt != 2 || scan.HighCnt != 3 {
		t.Errorf("严重度计数错误: crit=%d high=%d", scan.CriticalCnt, scan.HighCnt)
	}
	if scan.OS != "debian 12" {
		t.Errorf("OS 错误: %s", scan.OS)
	}
	if len(vulns) != 2 {
		t.Errorf("去重后应为 2 条漏洞，实际 %d", len(vulns))
	}
	if scan.TotalVulns != 2 {
		t.Errorf("TotalVulns 错误: %d", scan.TotalVulns)
	}
}

func TestParseVulnReport_EmptyRepo(t *testing.T) {
	report := &unstructured.Unstructured{Object: map[string]any{"report": map[string]any{}}}
	scan, _ := parseVulnReport(1, report)
	if scan != nil {
		t.Error("无 repository 应返回 nil")
	}
}
