package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "host"},
		{"host-01.local", "host-01.local"},
		{"host/01:abc", "host_01_abc"},
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestRunDiagProducesTarGz(t *testing.T) {
	old := execCommand
	defer func() { execCommand = old }()
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("fake-output\n"), nil
	}

	tmp := t.TempDir()
	logDir := filepath.Join(tmp, "logs")
	workDir := filepath.Join(tmp, "work")
	_ = os.MkdirAll(logDir, 0755)
	_ = os.MkdirAll(workDir, 0755)
	if err := os.WriteFile(filepath.Join(logDir, "agent.log"), []byte("log line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "agent_id"), []byte("test-agent-id"), 0600); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(tmp, "diag.tar.gz")
	var stdout, stderr bytes.Buffer
	got, err := RunDiag(
		CommonOptions{BuildVersion: "1.0.0", ServerHost: "h:1"},
		DiagOptions{OutputPath: outPath, LogDir: logDir, WorkDir: workDir},
		&stdout, &stderr,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != outPath {
		t.Errorf("path=%q want=%q", got, outPath)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatal("output file missing:", err)
	}

	// 解 tar.gz 检查内容
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	names := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		_, _ = io.Copy(&b, tr)
		names[hdr.Name] = b.String()
	}

	wanted := []string{"manifest.txt", "agent_id", "logs/agent.log", "system/uname.txt"}
	for _, w := range wanted {
		if _, ok := names[w]; !ok {
			t.Errorf("missing %s in tar; entries=%v", w, keys(names))
		}
	}
	if !strings.Contains(names["manifest.txt"], "Build version: 1.0.0") {
		t.Errorf("manifest missing version: %s", names["manifest.txt"])
	}
	if names["agent_id"] != "test-agent-id" {
		t.Errorf("agent_id content=%q", names["agent_id"])
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
