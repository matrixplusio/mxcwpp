package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

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

// TestRenderAlertmanagerWebhookAuth alertmanager 投递 manager 内部告警接口必须带认证，
// 而且带的是只对告警接收有效的那把，不是 internal_secret。
//
// 此前这里断言的正是「凭据等于 internal_secret」：那把同时保护 AC 的命令下发接口，
// 写进监控组件的配置文件等于把给 Agent 下发命令的权限交给了任何读得到这个文件的人。
func TestRenderAlertmanagerWebhookAuth(t *testing.T) {
	cfg := loadTestConfig(t, "testdata/ha-cluster.yaml")
	res, err := Render(cfg, RenderOptions{OutputDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	amPath := findGeneratedConfig(res, "alertmanager.yml")
	if amPath == "" {
		t.Fatal("未生成 alertmanager.yml")
	}
	raw, err := os.ReadFile(amPath)
	if err != nil {
		t.Fatal(err)
	}
	var am struct {
		Receivers []struct {
			WebhookConfigs []struct {
				URL        string `yaml:"url"`
				HTTPConfig struct {
					Authorization struct {
						Type        string `yaml:"type"`
						Credentials string `yaml:"credentials"`
					} `yaml:"authorization"`
				} `yaml:"http_config"`
			} `yaml:"webhook_configs"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal(raw, &am); err != nil {
		t.Fatalf("alertmanager.yml 不是合法 YAML: %v", err)
	}
	if len(am.Receivers) == 0 || len(am.Receivers[0].WebhookConfigs) == 0 {
		t.Fatal("alertmanager.yml 缺少 webhook receiver")
	}
	auth := am.Receivers[0].WebhookConfigs[0].HTTPConfig.Authorization
	if auth.Type != "Bearer" || auth.Credentials == "" || auth.Credentials != cfg.App.AlertIngestSecret {
		t.Errorf("webhook 认证 type=%q，凭据应为 alert_ingest_secret", auth.Type)
	}
	if auth.Credentials == cfg.App.InternalSecret {
		t.Error("alertmanager.yml 里不能出现 internal_secret")
	}
	if strings.Contains(string(raw), cfg.App.InternalSecret) || strings.Contains(string(raw), cfg.App.ACAdminSecret) {
		t.Error("alertmanager.yml 不得包含 internal_secret 或 ac_admin_secret")
	}
	if fi, _ := os.Stat(amPath); fi != nil && fi.Mode().Perm()&0o007 != 0 {
		t.Errorf("alertmanager.yml 不应对其它账号可读，权限 %o", fi.Mode().Perm())
	}
}

// TestRenderScopedSecrets_EachConfigOnlyGetsItsOwn 三把密钥互不相同；manager 侧配置拿告警接收的，
// AC 侧配置拿管理的，谁也不多拿；manager 用告警密钥启动、AC 用管理密钥启动都能过校验。
func TestRenderScopedSecrets_EachConfigOnlyGetsItsOwn(t *testing.T) {
	cfg := loadTestConfig(t, "testdata/ha-cluster.yaml")
	res, err := Render(cfg, RenderOptions{OutputDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	mgrCfg, err := config.Load(findGeneratedConfig(res, "server.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	acPath := findGeneratedConfig(res, "server-ac.yaml")
	acCfg, err := config.Load(acPath)
	if err != nil {
		t.Fatal(err)
	}
	if mgrCfg.Server.AlertIngestSecret == "" || mgrCfg.Server.ACAdminSecret != "" {
		t.Errorf("manager 侧应只有 alert_ingest_secret：alert 空=%v admin 空=%v",
			mgrCfg.Server.AlertIngestSecret == "", mgrCfg.Server.ACAdminSecret == "")
	}
	if acCfg.Server.ACAdminSecret == "" || acCfg.Server.AlertIngestSecret != "" {
		t.Errorf("AC 侧应只有 ac_admin_secret：admin 空=%v alert 空=%v",
			acCfg.Server.ACAdminSecret == "", acCfg.Server.AlertIngestSecret == "")
	}
	in, al, ad := mgrCfg.Server.InternalSecret, mgrCfg.Server.AlertIngestSecret, acCfg.Server.ACAdminSecret
	if in == al || in == ad || al == ad {
		t.Error("三把密钥必须互不相同")
	}
	// 证书路径指向本次渲染写出的文件（容器内路径在测试环境不存在），再跑完整启动校验
	acCertsDir := filepath.Join(filepath.Dir(filepath.Dir(acPath)), "certs")
	acCfg.MTLS.CACert = filepath.Join(acCertsDir, "ca.crt")
	acCfg.MTLS.CAKey = filepath.Join(acCertsDir, "ca.key")
	acCfg.MTLS.ServerCert = filepath.Join(acCertsDir, "server.crt")
	acCfg.MTLS.ServerKey = filepath.Join(acCertsDir, "server.key")
	if err := acCfg.ValidateAgentCenter(); err != nil {
		t.Errorf("渲染出的 AC 配置应能通过启动校验: %v", err)
	}
	if fi, _ := os.Stat(acPath); fi != nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("server-ac.yaml 权限应为 600，实际 %o", fi.Mode().Perm())
	}
}

// TestConfigPermsCmd 含密钥的配置文件上传后要显式设属主：只改模式的话，
// 以 uid 10001 运行的 engine / llmproxy / vulnsync 和以 65534 运行的 alertmanager 读不到配置。
func TestConfigPermsCmd(t *testing.T) {
	cmd := configPermsCmd("/opt/x/releases/r1")
	for _, want := range []string{
		"cd '/opt/x/releases/r1/config'",
		"chown 10001:0 server.yaml && chmod 640 server.yaml",
		"chown 0:0 server-ac.yaml && chmod 600 server-ac.yaml",
		"chown 0:65534 alertmanager.yml && chmod 640 alertmanager.yml",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("命令缺少 %q\n实际: %s", want, cmd)
		}
	}
}
