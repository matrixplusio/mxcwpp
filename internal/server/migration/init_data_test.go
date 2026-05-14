package migration

import (
	"testing"

	"github.com/imkerbos/mxsec-platform/internal/server/config"
)

func TestBuildManagedPluginDownloadURL(t *testing.T) {
	if got := buildManagedPluginDownloadURL(nil, "collector"); got != "/api/v1/plugins/download/collector" {
		t.Fatalf("default download URL = %q", got)
	}

	// 即使配置了 BaseURL，也始终返回相对路径（由 AC 端动态拼接完整地址）
	cfg := &config.PluginsConfig{
		BaseURL: "http://manager:8080/api/v1/plugins/download/",
	}
	if got := buildManagedPluginDownloadURL(cfg, "collector"); got != "/api/v1/plugins/download/collector" {
		t.Fatalf("should always return relative path, got = %q", got)
	}
}
