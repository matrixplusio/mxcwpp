package rule

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLoggerWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	al, err := NewAuditLogger(testLogger(t), path)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	al.Log(AuditEntry{
		RuleID:    "MXEDR-0001",
		RuleName:  "reverse_shell",
		Severity:  "critical",
		Action:    "kill",
		Enforce:   false,
		EventType: "process_exec",
		Target:    "12345",
		Result:    "skipped",
		Fields:    map[string]string{"exe": "/bin/bash"},
	})

	al.Log(AuditEntry{
		RuleID:    "MXEDR-0002",
		RuleName:  "crypto_miner",
		Severity:  "high",
		Action:    "alert",
		Enforce:   false,
		EventType: "tcp_connect",
		Target:    "3333",
		Result:    "executed",
	})

	// Read and verify log file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := splitLines(data)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var entry1 AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry1); err != nil {
		t.Fatal(err)
	}
	if entry1.RuleID != "MXEDR-0001" {
		t.Errorf("entry1 RuleID = %q", entry1.RuleID)
	}
	if entry1.Timestamp == "" {
		t.Error("timestamp should be set")
	}
	if entry1.Result != "skipped" {
		t.Errorf("result = %q", entry1.Result)
	}
	if entry1.Fields["exe"] != "/bin/bash" {
		t.Errorf("fields.exe = %q", entry1.Fields["exe"])
	}

	var entry2 AuditEntry
	if err := json.Unmarshal([]byte(lines[1]), &entry2); err != nil {
		t.Fatal(err)
	}
	if entry2.RuleID != "MXEDR-0002" {
		t.Errorf("entry2 RuleID = %q", entry2.RuleID)
	}
}

func TestAuditLoggerCreateDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "audit.log")

	al, err := NewAuditLogger(testLogger(t), path)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	al.Log(AuditEntry{RuleID: "TEST", Action: "alert", Result: "executed"})

	if _, err := os.Stat(path); err != nil {
		t.Errorf("audit file not created: %v", err)
	}
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			line := string(data[start:i])
			if line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(data) {
		line := string(data[start:])
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
