package mql

import (
	"strings"
	"testing"
)

func TestLexBasic(t *testing.T) {
	tokens, err := Lex(`search events | where event_type == "process_exec"`)
	if err != nil {
		t.Fatal(err)
	}
	// search(ident) events(ident) |(pipe) where(ident) event_type(ident) ==(eq) "process_exec"(string) EOF
	if len(tokens) != 8 {
		t.Fatalf("expected 8 tokens, got %d", len(tokens))
	}
	if tokens[0].Type != TokIdent || tokens[0].Val != "search" {
		t.Errorf("token[0]: got %v", tokens[0])
	}
	if tokens[5].Type != TokEq {
		t.Errorf("token[5] should be ==, got %v", tokens[5])
	}
	if tokens[6].Type != TokString || tokens[6].Val != "process_exec" {
		t.Errorf("token[6]: got %v", tokens[6])
	}
}

func TestParseBasicWhere(t *testing.T) {
	q, err := Parse(`search events | where event_type == "process_exec" | limit 50`)
	if err != nil {
		t.Fatal(err)
	}
	if q.Source != "events" {
		t.Errorf("source: got %q", q.Source)
	}
	if len(q.Wheres) != 1 {
		t.Fatalf("wheres: got %d", len(q.Wheres))
	}
	if q.Wheres[0].Field != "event_type" {
		t.Errorf("where field: got %q", q.Wheres[0].Field)
	}
	if q.Wheres[0].Op != OpEq {
		t.Errorf("where op: got %v", q.Wheres[0].Op)
	}
	if q.Wheres[0].Value != "process_exec" {
		t.Errorf("where value: got %q", q.Wheres[0].Value)
	}
	if q.Limit != 50 {
		t.Errorf("limit: got %d", q.Limit)
	}
}

func TestParseMultipleWheres(t *testing.T) {
	q, err := Parse(`search events | where event_type == "process_exec" | where cmdline contains "/dev/tcp/" | where timestamp > now() - 24h`)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Wheres) != 3 {
		t.Fatalf("expected 3 wheres, got %d", len(q.Wheres))
	}
	if q.Wheres[1].Op != OpContains {
		t.Errorf("where[1] op: got %v", q.Wheres[1].Op)
	}
	if q.Wheres[2].Field != "timestamp" {
		t.Errorf("where[2] field: got %q", q.Wheres[2].Field)
	}
}

func TestParseStats(t *testing.T) {
	q, err := Parse(`search events | where event_type == "tcp_connect" | stats count() as total, unique_count(remote_addr) as ips by host_id | where total > 50 | sort total desc`)
	if err != nil {
		t.Fatal(err)
	}
	if q.Stats == nil {
		t.Fatal("expected stats clause")
	}
	if len(q.Stats.Aggregations) != 2 {
		t.Fatalf("expected 2 aggregations, got %d", len(q.Stats.Aggregations))
	}
	if q.Stats.Aggregations[0].Func != "count" || q.Stats.Aggregations[0].Alias != "total" {
		t.Errorf("agg[0]: %+v", q.Stats.Aggregations[0])
	}
	if q.Stats.Aggregations[1].Func != "unique_count" || q.Stats.Aggregations[1].Field != "remote_addr" {
		t.Errorf("agg[1]: %+v", q.Stats.Aggregations[1])
	}
	if len(q.Stats.GroupBy) != 1 || q.Stats.GroupBy[0] != "host_id" {
		t.Errorf("group by: got %v", q.Stats.GroupBy)
	}
	// "where total > 50" after stats → goes into Having.
	if len(q.Having) != 1 {
		t.Fatalf("expected 1 having, got %d", len(q.Having))
	}
	if q.Having[0].Field != "total" {
		t.Errorf("having field: got %q", q.Having[0].Field)
	}
}

func TestCompileBasic(t *testing.T) {
	q, err := Parse(`search events | where event_type == "process_exec" | sort timestamp desc | limit 20`)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compile(q)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.SQL, "FROM ebpf_events") {
		t.Error("SQL should reference ebpf_events")
	}
	if !strings.Contains(result.SQL, "event_type = ?") {
		t.Error("SQL should have parameterized where clause")
	}
	if !strings.Contains(result.SQL, "ORDER BY timestamp DESC") {
		t.Error("SQL should have ORDER BY")
	}
	if !strings.Contains(result.SQL, "LIMIT 20") {
		t.Error("SQL should have LIMIT 20")
	}
	if len(result.Args) != 1 || result.Args[0] != "process_exec" {
		t.Errorf("args: got %v", result.Args)
	}
}

func TestCompileStats(t *testing.T) {
	q, err := Parse(`search events | where event_type == "tcp_connect" | stats count() as total by host_id | where total > 100 | sort total desc`)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compile(q)
	if err != nil {
		t.Fatal(err)
	}

	if !result.IsAgg {
		t.Error("should be aggregation query")
	}
	if !strings.Contains(result.SQL, "count()") {
		t.Error("SQL should have count()")
	}
	if !strings.Contains(result.SQL, "GROUP BY host_id") {
		t.Error("SQL should have GROUP BY")
	}
	if !strings.Contains(result.SQL, "HAVING") {
		t.Error("SQL should have HAVING clause")
	}
}

func TestCompileContains(t *testing.T) {
	q, err := Parse(`search events | where cmdline contains "/dev/tcp/"`)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compile(q)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.SQL, "position(cmdline, ?) > 0") {
		t.Errorf("SQL should use position() for contains, got: %s", result.SQL)
	}
}

func TestCompileTimestamp(t *testing.T) {
	q, err := Parse(`search events | where timestamp > now() - 24h`)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compile(q)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.SQL, "INTERVAL") {
		t.Errorf("SQL should use INTERVAL for time expressions, got: %s", result.SQL)
	}
}

func TestCompileNot(t *testing.T) {
	q, err := Parse(`search events | where NOT exe startswith "/usr/"`)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compile(q)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.SQL, "NOT startsWith(exe, ?)") {
		t.Errorf("SQL should have NOT prefix, got: %s", result.SQL)
	}
}

func TestCompileIn(t *testing.T) {
	q, err := Parse(`search events | where exe in ("bash", "sh", "python")`)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compile(q)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.SQL, "IN (?, ?, ?)") {
		t.Errorf("SQL should have IN clause, got: %s", result.SQL)
	}
	if len(result.Args) != 3 {
		t.Errorf("expected 3 args for IN, got %d", len(result.Args))
	}
}

func TestMaxLimitEnforced(t *testing.T) {
	q, err := Parse(`search events | limit 99999`)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Compile(q)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.SQL, "LIMIT 10000") {
		t.Errorf("limit should be capped at 10000, got: %s", result.SQL)
	}
}

func TestUnknownField(t *testing.T) {
	q, err := Parse(`search events | where badfield == "x"`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Compile(q)
	if err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestUnknownSource(t *testing.T) {
	q, err := Parse(`search badtable | limit 10`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Compile(q)
	if err == nil {
		t.Error("expected error for unknown source")
	}
}
