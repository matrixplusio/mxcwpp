package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectConfig(t *testing.T) {
	r := collectConfig(CommonOptions{BuildVersion: "1.0.0", ServerHost: "10.0.0.1:6751"})
	if r.BuildVersion != "1.0.0" {
		t.Errorf("BuildVersion=%q", r.BuildVersion)
	}
	if r.ServerHost != "10.0.0.1:6751" {
		t.Errorf("ServerHost=%q", r.ServerHost)
	}
}

func TestHasCertBundle(t *testing.T) {
	dir := t.TempDir()
	if hasCertBundle(dir) {
		t.Fatal("expected no bundle in empty dir")
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// readFile 是包级变量，需切换到本目录读取
	old := readFile
	readFile = func(p string) ([]byte, error) {
		return os.ReadFile(p)
	}
	defer func() { readFile = old }()
	if !hasCertBundle(dir) {
		t.Fatal("expected bundle present")
	}
}

func TestRunConfigJSON(t *testing.T) {
	var buf bytes.Buffer
	err := RunConfig(CommonOptions{BuildVersion: "1.0.0", JSON: true}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	var r ConfigReport
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
}

func TestRunConfigText(t *testing.T) {
	var buf bytes.Buffer
	if err := RunConfig(CommonOptions{}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Build version:") {
		t.Errorf("missing Build version: %s", buf.String())
	}
}
