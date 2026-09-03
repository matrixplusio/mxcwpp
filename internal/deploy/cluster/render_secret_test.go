package cluster

import (
	"path/filepath"
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

// findGeneratedConfig 在所有节点 bundle 中查找指定配置文件名并返回其路径。
func findGeneratedConfig(res *RenderResult, name string) string {
	for _, nb := range res.NodeBundles {
		p := filepath.Join(nb.BundleDir, "config", name)
		if matches, _ := filepath.Glob(p); len(matches) == 1 {
			return matches[0]
		}
	}
	return ""
}

// TestRenderInternalSecret_ManagerAndACShareStrongSecret 断言集群渲染出的 manager
// server.yaml 与 agentcenter server-ac.yaml 携带同一非空强 internal_secret，
// 且生成的 AC 配置能通过 ValidateAgentCenter（可启动，不被 fail-closed 拒绝）。
func TestRenderInternalSecret_ManagerAndACShareStrongSecret(t *testing.T) {
	cfg := loadTestConfig(t, "testdata/ha-cluster.yaml")
	outDir := t.TempDir()
	res, err := Render(cfg, RenderOptions{OutputDir: outDir})
	if err != nil {
		t.Fatal(err)
	}

	mgrPath := findGeneratedConfig(res, "server.yaml")
	acPath := findGeneratedConfig(res, "server-ac.yaml")
	if mgrPath == "" || acPath == "" {
		t.Fatalf("未生成 server.yaml(%q) 或 server-ac.yaml(%q)", mgrPath, acPath)
	}

	mgrCfg, err := config.Load(mgrPath)
	if err != nil {
		t.Fatalf("load manager server.yaml: %v", err)
	}
	acCfg, err := config.Load(acPath)
	if err != nil {
		t.Fatalf("load server-ac.yaml: %v", err)
	}

	if mgrCfg.Server.InternalSecret == "" {
		t.Error("manager server.yaml 缺少 internal_secret")
	}
	if mgrCfg.Server.InternalSecret != acCfg.Server.InternalSecret {
		t.Errorf("Manager 与 AC 的 internal_secret 不一致: %q vs %q",
			mgrCfg.Server.InternalSecret, acCfg.Server.InternalSecret)
	}
	if acCfg.Server.HTTP.Host != "0.0.0.0" {
		t.Errorf("AC HTTP host = %q, 期望 0.0.0.0（外部可达）", acCfg.Server.HTTP.Host)
	}

	// 信任链渲染断言：一机一证 + 强制身份绑定 + 强 enroll token 必须默认开启。
	if !acCfg.MTLS.PerAgentCert || !acCfg.MTLS.EnforceAgentID {
		t.Errorf("AC 配置应默认开启 per_agent_cert / enforce_agent_id，得 per=%v enforce=%v",
			acCfg.MTLS.PerAgentCert, acCfg.MTLS.EnforceAgentID)
	}
	if err := config.ValidateEnrollToken(acCfg.MTLS.EnrollToken); err != nil {
		t.Errorf("渲染的 enroll_token 未达强度: %v", err)
	}

	// 核心断言：把 mtls 证书路径指向本次渲染实际写出的证书文件（容器内路径 /etc/mxcwpp/certs
	// 在测试环境不存在），再跑完整 fail-closed 校验——官方渲染结果必须通过强校验。
	acCertsDir := filepath.Join(filepath.Dir(filepath.Dir(acPath)), "certs")
	acCfg.MTLS.CACert = filepath.Join(acCertsDir, "ca.crt")
	acCfg.MTLS.CAKey = filepath.Join(acCertsDir, "ca.key")
	acCfg.MTLS.ServerCert = filepath.Join(acCertsDir, "server.crt")
	acCfg.MTLS.ServerKey = filepath.Join(acCertsDir, "server.key")
	if err := acCfg.ValidateAgentCenter(); err != nil {
		t.Errorf("生成的 AC 配置无法通过 ValidateAgentCenter: %v", err)
	}
}

// TestClusterValidate_InternalSecretRequired 集群配置缺失/弱 internal_secret 时校验失败。
func TestClusterValidate_InternalSecretRequired(t *testing.T) {
	base := loadTestConfig(t, "testdata/ha-cluster.yaml")

	cases := []struct {
		name, secret string
		wantErr      bool
	}{
		{"empty", "", true},
		{"placeholder", "__REPLACE__", true},
		{"weak", "change-me-padding-to-reach-32-chars!", true},
		{"strong", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", false},
	}
	for _, c := range cases {
		cp := *base
		cp.App.InternalSecret = c.secret
		err := cp.Validate()
		if c.wantErr && err == nil {
			t.Errorf("%s: expected validate error, got nil", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: expected nil, got %v", c.name, err)
		}
	}
}
