package transfer

import (
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestBuildPluginDownloadURLsSkipsLegacyFileURL(t *testing.T) {
	svc := &Service{
		logger: zap.NewNop(),
		cfg: &config.Config{
			Server: config.ServerConfig{
				HTTP: config.HTTPConfig{Port: 8080},
				GRPC: config.GRPCConfig{Host: "agentcenter"},
			},
		},
	}

	got := svc.buildPluginDownloadURLs([]string{
		"file:///workspace/dist/plugins/collector",
		"http://manager:8080/api/v1/plugins/download/collector",
	}, "collector")

	if len(got) != 1 {
		t.Fatalf("len(downloadURLs) = %d, want 1", len(got))
	}
	if got[0] != "http://manager:8080/api/v1/plugins/download/collector" {
		t.Fatalf("downloadURLs[0] = %q", got[0])
	}
}

func TestPluginConfigUsesManagerDownload(t *testing.T) {
	svc := &Service{
		cfg: &config.Config{
			Plugins: config.PluginsConfig{
				BaseURL: "http://manager:8080/api/v1/plugins/download",
			},
		},
	}

	pc := model.PluginConfig{Name: "collector"}

	if !svc.pluginConfigUsesManagerDownload(pc, []string{"/api/v1/plugins/download/collector"}) {
		t.Fatal("relative manager download URL should be treated as manager-hosted")
	}
	if !svc.pluginConfigUsesManagerDownload(pc, []string{"http://manager:8080/api/v1/plugins/download/collector"}) {
		t.Fatal("absolute manager download URL should be treated as manager-hosted")
	}
	if svc.pluginConfigUsesManagerDownload(pc, []string{"https://artifact.example.com/collector"}) {
		t.Fatal("external download URL should not be treated as manager-hosted")
	}
}
