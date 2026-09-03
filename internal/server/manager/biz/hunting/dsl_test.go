package hunting

import "testing"

func TestCompileBasic(t *testing.T) {
	q, err := Compile(`source="alerts" severity="critical" | where host_id="h-1" | sort -count | head 10`)
	if err != nil {
		t.Fatal(err)
	}
	if q.Source != "alerts" {
		t.Errorf("source=%s", q.Source)
	}
	if len(q.Stages) != 4 {
		t.Errorf("stages=%d", len(q.Stages))
	}
}

func TestSQLGen(t *testing.T) {
	q, err := Compile(`source="alerts" severity="critical" | where host_id="h-1" | sort -created_at | head 50`)
	if err != nil {
		t.Fatal(err)
	}
	sql, args, err := q.SQL(200)
	if err != nil {
		t.Fatal(err)
	}
	if sql == "" || len(args) < 2 {
		t.Errorf("sql=%q args=%v", sql, args)
	}
}

func TestInvalidIdent(t *testing.T) {
	q, _ := Compile(`source="al;DROP" foo="bar"`)
	if _, _, err := q.SQL(100); err == nil {
		t.Fatal("expected error for invalid source")
	}
}
