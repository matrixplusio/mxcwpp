package transfer

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func newPluginTestService(t *testing.T) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	db.Exec("CREATE TABLE system_configs (id INTEGER PRIMARY KEY, `key` TEXT, category TEXT, value TEXT)")
	db.Exec("INSERT INTO system_configs (`key`, category, value) VALUES ('site_config','site','{\"backend_url\":\"https://ac.example\"}')")
	return &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop()}
}

func globalPlugins() []model.PluginConfig {
	return []model.PluginConfig{
		{Name: "fim", Type: "fim", Version: "1.0.1", SHA256: "sha-old", Signature: "sig-old",
			DownloadURLs: model.StringArray{"/api/v1/plugins/download/fim"}, Detail: "{}"},
		{Name: "collector", Type: "collector", Version: "1.0.2", SHA256: "sha-col",
			DownloadURLs: model.StringArray{"/api/v1/plugins/download/collector"}},
		{Name: "kube-only", Type: "x", Version: "1", SHA256: "sha-k", RuntimeTypes: model.StringArray{"k8s"},
			DownloadURLs: model.StringArray{"/api/v1/plugins/download/kube-only"}},
	}
}

// TestBuildPluginConfigs_NoCanaryUnchanged 没有灰度时，下发内容与改造前完全一致：
// 全局版本、相对地址按 backend_url 拼全、运行时不匹配的插件照旧跳过。
func TestBuildPluginConfigs_NoCanaryUnchanged(t *testing.T) {
	s := newPluginTestService(t)
	got := s.buildPluginConfigs(globalPlugins(), nil, "agent-1", model.RuntimeTypeVM)
	if len(got) != 2 {
		t.Fatalf("vm 主机应拿到 2 个插件，实际 %d", len(got))
	}
	f := got[0]
	if f.Name != "fim" || f.Version != "1.0.1" || f.Sha256 != "sha-old" || f.Signature != "sig-old" || f.Detail != "{}" ||
		len(f.DownloadUrls) != 1 || f.DownloadUrls[0] != "https://ac.example/api/v1/plugins/download/fim" {
		t.Fatalf("无灰度时 fim 配置被改变: %+v", f)
	}
}

// TestBuildPluginConfigs_CanaryOnlyForListedHosts 灰度只覆盖名单内主机的该插件，下载地址带版本号。
func TestBuildPluginConfigs_CanaryOnlyForListedHosts(t *testing.T) {
	s := newPluginTestService(t)
	canaries := map[string]model.PluginCanary{
		"fim": {PluginName: "fim", Version: "1.0.2", SHA256: "sha-new", Signature: "sig-new", HostIDs: model.StringArray{"agent-1"}},
	}

	in := s.buildPluginConfigs(globalPlugins(), canaries, "agent-1", model.RuntimeTypeVM)
	f := in[0]
	if f.Version != "1.0.2" || f.Sha256 != "sha-new" || f.Signature != "sig-new" ||
		f.DownloadUrls[0] != "https://ac.example/api/v1/plugins/download/fim?version=1.0.2" {
		t.Fatalf("灰度主机应拿到灰度版本: %+v", f)
	}
	if in[1].Name != "collector" || in[1].Version != "1.0.2" || in[1].Sha256 != "sha-col" {
		t.Fatalf("其它插件不应受灰度影响: %+v", in[1])
	}

	out := s.buildPluginConfigs(globalPlugins(), canaries, "agent-2", model.RuntimeTypeVM)
	if out[0].Version != "1.0.1" || out[0].Sha256 != "sha-old" {
		t.Fatalf("名单外主机应保持全局版本: %+v", out[0])
	}

	// 覆盖只作用于本次构造，不能改到调用方传入的全局配置
	g := globalPlugins()
	s.buildPluginConfigs(g, canaries, "agent-1", model.RuntimeTypeVM)
	if g[0].Version != "1.0.1" {
		t.Fatal("灰度覆盖改写了全局配置切片")
	}
}

// 全新插件的占位配置没有下载地址：灰度名单外的主机拿不到它，名单内的拿到灰度版本。
func TestBuildPluginConfigs_PlaceholderOnlyForCanaryHosts(t *testing.T) {
	s := newPluginTestService(t)
	plugins := append(globalPlugins(), model.PluginConfig{Name: "logcollector", Type: "logcollector",
		DownloadURLs: model.StringArray{}, RuntimeTypes: model.StringArray{"vm"}, Enabled: true})
	canaries := map[string]model.PluginCanary{
		"logcollector": {PluginName: "logcollector", Version: "1.0.0", SHA256: "sha-lc", Signature: "sig-lc", HostIDs: model.StringArray{"agent-1"}},
	}
	has := func(agent string) bool {
		for _, c := range s.buildPluginConfigs(plugins, canaries, agent, model.RuntimeTypeVM) {
			if c.Name == "logcollector" {
				if c.Version != "1.0.0" || c.Sha256 != "sha-lc" || len(c.DownloadUrls) != 1 {
					t.Fatalf("灰度主机拿到的配置不对: %+v", c)
				}
				return true
			}
		}
		return false
	}
	if !has("agent-1") {
		t.Fatal("灰度名单内的主机应拿到插件")
	}
	if has("agent-2") {
		t.Fatal("名单外的主机不能拿到占位插件")
	}
	if got := s.buildPluginConfigs(plugins, nil, "agent-1", model.RuntimeTypeVM); len(got) != 2 {
		t.Fatalf("没有灰度时占位插件不下发，应只有原来的 2 个，实际 %d", len(got))
	}
}
