package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadTestConfig(t *testing.T, path string) *Config {
	t.Helper()
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("loadTestConfig(%s): %v", path, err)
	}
	return cfg
}

type testBundle struct {
	Compose string
}

// bundleFor finds the NodeBundle for node name and returns concatenated compose file content.
func bundleFor(res *RenderResult, name string) testBundle {
	for _, nb := range res.NodeBundles {
		if nb.Node.Name == name {
			files, _ := filepath.Glob(filepath.Join(nb.BundleDir, "compose", "*.yml"))
			var sb strings.Builder
			for _, f := range files {
				data, err := os.ReadFile(f)
				if err == nil {
					sb.Write(data)
				}
			}
			return testBundle{Compose: sb.String()}
		}
	}
	return testBundle{}
}

// TestRenderLegacyGolden verifies that a coarse-role config (control/storage/kafka)
// renders all 7 app services in the control compose and no app services in the storage compose.
func TestRenderLegacyGolden(t *testing.T) {
	cfg := loadTestConfig(t, "testdata/legacy-cluster.yaml")
	outDir := t.TempDir()
	res, err := Render(cfg, RenderOptions{OutputDir: outDir})
	if err != nil {
		t.Fatal(err)
	}
	control := bundleFor(res, "n1-control")
	for _, svc := range []string{"manager", "agentcenter", "consumer", "engine", "vulnsync", "llmproxy", "ui"} {
		if !strings.Contains(control.Compose, svc+":") {
			t.Errorf("control compose missing %s", svc)
		}
	}
	storage := bundleFor(res, "n2-storage")
	// Use "\n  manager:" to match the YAML service key specifically;
	// plain "manager:" also matches "alertmanager:" which is expected in storage.
	if strings.Contains(storage.Compose, "\n  manager:") {
		t.Error("storage compose should NOT contain manager")
	}
}

// TestRenderHASplit verifies that fine-grained HA roles emit only the correct service blocks.
func TestRenderHASplit(t *testing.T) {
	cfg := loadTestConfig(t, "testdata/ha-cluster.yaml")
	outDir := t.TempDir()
	res, err := Render(cfg, RenderOptions{OutputDir: outDir})
	if err != nil {
		t.Fatal(err)
	}
	ac := bundleFor(res, "n2")
	if strings.Contains(ac.Compose, "manager:") {
		t.Error("AC-only node must not render manager")
	}
	if !strings.Contains(ac.Compose, "agentcenter:") {
		t.Error("AC node must render agentcenter")
	}
	mgr := bundleFor(res, "n1")
	if !strings.Contains(mgr.Compose, "mxcwpp-manager:v1.0.2") {
		t.Error("manager image should use component version v1.0.2")
	}
}
