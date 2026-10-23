package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// 集群对象会经列表接口原样序列化给只读用户，凭证字段一个都不能带出去。
func TestKubeClusterJSONOmitsCredentials(t *testing.T) {
	b, err := json.Marshal(KubeCluster{KubeConfig: "kc-secret", AuditToken: "tok-secret", GCPCredentialsJSON: "gcp-secret"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"kc-secret", "tok-secret", "gcp-secret"} {
		if strings.Contains(string(b), s) {
			t.Errorf("序列化结果带出了凭证 %q: %s", s, b)
		}
	}
}
