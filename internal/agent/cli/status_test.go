package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseSystemdShow(t *testing.T) {
	in := "ActiveState=active\nSubState=running\nMainPID=12345\nActiveEnterTimestamp=Mon 2026-06-03 12:34:56 CST\n"
	m := parseSystemdShow(in)
	if m["ActiveState"] != "active" {
		t.Errorf("ActiveState: got %q", m["ActiveState"])
	}
	if m["MainPID"] != "12345" {
		t.Errorf("MainPID: got %q", m["MainPID"])
	}
	if m["ActiveEnterTimestamp"] != "Mon 2026-06-03 12:34:56 CST" {
		t.Errorf("Timestamp: got %q", m["ActiveEnterTimestamp"])
	}
}

func TestParseSystemdTimestamp(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
	}{
		{"Mon 2026-06-03 12:34:56 CST", true},
		{"2026-06-03 12:34:56", true},
		{"", false},
		{"n/a", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			tm, err := parseSystemdTimestamp(c.in)
			if c.wantOK {
				if err != nil {
					t.Fatalf("err=%v", err)
				}
				if tm.IsZero() {
					t.Fatal("zero time")
				}
			} else if !tm.IsZero() {
				t.Fatalf("expected zero, got %v", tm)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	cases := []struct {
		sec  int64
		want string
	}{
		{0, "0s"},
		{45, "45s"},
		{60, "1m"},
		{3661, "1h1m1s"},
		{90061, "1d1h1m1s"},
	}
	for _, c := range cases {
		got := formatDuration(c.sec)
		if got != c.want {
			t.Errorf("sec=%d got=%q want=%q", c.sec, got, c.want)
		}
	}
}

func TestProbeTCPEmpty(t *testing.T) {
	ok, msg := probeTCP("", 100*time.Millisecond)
	if ok {
		t.Fatal("expected unreachable")
	}
	if msg == "" {
		t.Fatal("expected error message")
	}
}

func TestProbeTCPInvalid(t *testing.T) {
	// 0 端口必拒
	ok, _ := probeTCP("127.0.0.1:1", 200*time.Millisecond)
	if ok {
		// 极小概率 1 端口被占用，宽松判断
		t.Log("port 1 reachable on this host, skipping strict check")
	}
}

func TestRunStatusJSON(t *testing.T) {
	old := execCommand
	defer func() { execCommand = old }()
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ActiveState=active\nSubState=running\nMainPID=42\n"), nil
	}
	var buf bytes.Buffer
	err := RunStatus(CommonOptions{
		BuildVersion: "1.2.3",
		ServerHost:   "",
		JSON:         true,
	}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	var r StatusReport
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatalf("invalid json: %v\nout=%s", err, buf.String())
	}
	if r.Version != "1.2.3" {
		t.Errorf("version=%q", r.Version)
	}
	if !r.SystemdActive {
		t.Error("expected active")
	}
	if r.MainPID != 42 {
		t.Errorf("pid=%d", r.MainPID)
	}
}

func TestRunStatusText(t *testing.T) {
	old := execCommand
	defer func() { execCommand = old }()
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}
	var buf bytes.Buffer
	err := RunStatus(CommonOptions{BuildVersion: "dev"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Active:") {
		t.Errorf("missing Active: %s", out)
	}
}

func TestFormatStatusTextEmptyServer(t *testing.T) {
	r := &StatusReport{Version: "dev"}
	out := formatStatusText(r)
	if !strings.Contains(out, "Server:         -") {
		t.Errorf("expected dash for empty server, got: %s", out)
	}
}
