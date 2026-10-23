package config

import (
	"strings"
	"testing"
)

const (
	strongA = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	strongB = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	strongC = "9a8b7c6d5e4f30211203f4e5d6c7b8a9"
)

// TestValidateScopedSecrets 拆出来的密钥：不配可以，配了就得够强，且不能和 internal_secret 是同一把
// ——同一把就等于没拆，监控组件仍然握着能下发命令的密钥。
func TestValidateScopedSecrets(t *testing.T) {
	cases := []struct {
		name                         string
		internal, alert, admin, prev string
		wantErr                      string
	}{
		{"都不配", strongA, "", "", "", ""},
		{"各不相同", strongA, strongB, strongC, "", ""},
		{"告警密钥与内部密钥相同", strongA, strongA, "", "", "alert_ingest_secret"},
		{"管理密钥与内部密钥相同", strongA, "", strongA, "", "ac_admin_secret"},
		{"管理密钥与告警密钥相同", strongA, strongB, strongB, "", "ac_admin_secret"},
		{"告警密钥太短", strongA, "short", "", "", "alert_ingest_secret"},
		{"过渡密钥太弱", strongA, "", "", "changeme", "internal_secret_extra"},
		{"过渡密钥与另两把都不同", strongA, strongB, "", strongC, ""},
		// 旧的 internal_secret 改当告警密钥、同时留作过渡密钥：告警密钥就又能下发命令了
		{"过渡密钥与告警密钥相同", strongA, strongB, "", strongB, "internal_secret_extra"},
		{"过渡密钥与管理密钥相同", strongA, "", strongB, strongB, "internal_secret_extra"},
		{"过渡密钥与内部密钥相同", strongA, "", "", strongA, "internal_secret_extra"},
	}
	for _, c := range cases {
		cfg := &Config{}
		cfg.Server.InternalSecret = c.internal
		cfg.Server.AlertIngestSecret = c.alert
		cfg.Server.ACAdminSecret = c.admin
		cfg.Server.InternalSecretExtra = c.prev
		err := cfg.validateScopedSecrets()
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: 不应报错，实际 %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: 应报 %s 相关错误，实际 %v", c.name, c.wantErr, err)
		}
	}
}
