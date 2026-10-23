package mql

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CompileResult holds the generated ClickHouse SQL and parameters.
type CompileResult struct {
	SQL   string
	Args  []any
	IsAgg bool // true if query uses stats (aggregation)
}

// Safety limits.
const (
	MaxLimit     = 10000
	DefaultLimit = 100
	MaxTimeSpan  = 90 * 24 * time.Hour // 90 days
)

// validFields are the ClickHouse ebpf_events columns that MQL can reference.
var validFields = map[string]bool{
	"timestamp":   true,
	"host_id":     true,
	"hostname":    true,
	"event_type":  true,
	"data_type":   true,
	"pid":         true,
	"ppid":        true,
	"exe":         true,
	"cmdline":     true,
	"parent_exe":  true,
	"file_path":   true,
	"remote_addr": true,
	"remote_port": true,
	"local_addr":  true,
	"local_port":  true,
	"protocol":    true,
	"uid":         true,
	"gid":         true,
	"return_code": true,
}

// sourceTable maps MQL source names to ClickHouse tables.
var sourceTable = map[string]string{
	"events": "ebpf_events",
}

// Compile converts an MQL AST to a ClickHouse SQL query.
func Compile(q *Query) (*CompileResult, error) {
	table, ok := sourceTable[q.Source]
	if !ok {
		return nil, fmt.Errorf("unknown source %q (available: events)", q.Source)
	}

	r := &CompileResult{}

	if q.Stats != nil {
		return compileAgg(q, table, r)
	}
	return compileSelect(q, table, r)
}

func compileSelect(q *Query, table string, r *CompileResult) (*CompileResult, error) {
	var sb strings.Builder

	sb.WriteString("SELECT timestamp, host_id, hostname, event_type, data_type, ")
	sb.WriteString("pid, ppid, exe, cmdline, parent_exe, ")
	sb.WriteString("file_path, remote_addr, remote_port, local_addr, local_port, ")
	sb.WriteString("protocol, uid, gid, return_code ")
	sb.WriteString("FROM ")
	sb.WriteString(table)

	// WHERE clauses.
	if len(q.Wheres) > 0 {
		sb.WriteString(" WHERE ")
		for i, w := range q.Wheres {
			if i > 0 {
				sb.WriteString(" AND ")
			}
			clause, args, err := compileCondition(w)
			if err != nil {
				return nil, err
			}
			sb.WriteString(clause)
			r.Args = append(r.Args, args...)
		}
	}

	// ORDER BY.
	if len(q.Sort) > 0 {
		sb.WriteString(" ORDER BY ")
		for i, s := range q.Sort {
			if i > 0 {
				sb.WriteString(", ")
			}
			if err := validateField(s.Field); err != nil {
				return nil, err
			}
			sb.WriteString(s.Field)
			if s.Desc {
				sb.WriteString(" DESC")
			} else {
				sb.WriteString(" ASC")
			}
		}
	} else {
		sb.WriteString(" ORDER BY timestamp DESC")
	}

	// LIMIT.
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	sb.WriteString(" LIMIT ")
	sb.WriteString(strconv.Itoa(limit))

	r.SQL = sb.String()
	return r, nil
}

func compileAgg(q *Query, table string, r *CompileResult) (*CompileResult, error) {
	r.IsAgg = true
	var sb strings.Builder

	sb.WriteString("SELECT ")

	// GROUP BY fields.
	for _, g := range q.Stats.GroupBy {
		if err := validateField(g); err != nil {
			return nil, err
		}
		sb.WriteString(g)
		sb.WriteString(", ")
	}

	// Aggregation functions.
	for i, agg := range q.Stats.Aggregations {
		if i > 0 {
			sb.WriteString(", ")
		}
		expr, err := compileAggFunc(agg)
		if err != nil {
			return nil, err
		}
		sb.WriteString(expr)
		sb.WriteString(" AS ")
		sb.WriteString(agg.Alias)
	}

	sb.WriteString(" FROM ")
	sb.WriteString(table)

	// WHERE clauses (before aggregation).
	if len(q.Wheres) > 0 {
		sb.WriteString(" WHERE ")
		for i, w := range q.Wheres {
			if i > 0 {
				sb.WriteString(" AND ")
			}
			clause, args, err := compileCondition(w)
			if err != nil {
				return nil, err
			}
			sb.WriteString(clause)
			r.Args = append(r.Args, args...)
		}
	}

	// GROUP BY.
	if len(q.Stats.GroupBy) > 0 {
		sb.WriteString(" GROUP BY ")
		sb.WriteString(strings.Join(q.Stats.GroupBy, ", "))
	}

	// HAVING (where after stats).
	if len(q.Having) > 0 {
		sb.WriteString(" HAVING ")
		for i, h := range q.Having {
			if i > 0 {
				sb.WriteString(" AND ")
			}
			// Having uses aliases directly.
			clause, args, err := compileHavingCondition(h)
			if err != nil {
				return nil, err
			}
			sb.WriteString(clause)
			r.Args = append(r.Args, args...)
		}
	}

	// ORDER BY.
	if len(q.Sort) > 0 {
		sb.WriteString(" ORDER BY ")
		for i, s := range q.Sort {
			if i > 0 {
				sb.WriteString(", ")
			}
			// Sort can reference aliases or fields.
			sb.WriteString(s.Field)
			if s.Desc {
				sb.WriteString(" DESC")
			} else {
				sb.WriteString(" ASC")
			}
		}
	}

	// LIMIT.
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	sb.WriteString(" LIMIT ")
	sb.WriteString(strconv.Itoa(limit))

	r.SQL = sb.String()
	return r, nil
}

func compileCondition(c Condition) (string, []any, error) {
	// Handle built-in function conditions.
	if c.Function != "" {
		return compileFuncCondition(c)
	}

	if err := validateField(c.Field); err != nil {
		// Special case: timestamp comparison with now() expressions.
		if c.Field != "timestamp" {
			return "", nil, err
		}
	}

	prefix := ""
	if c.Negate {
		prefix = "NOT "
	}

	switch c.Op {
	case OpEq:
		return prefix + c.Field + " = ?", []any{c.Value}, nil
	case OpNeq:
		return prefix + c.Field + " != ?", []any{c.Value}, nil
	case OpGt:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " > " + val, args, nil
	case OpGte:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " >= " + val, args, nil
	case OpLt:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " < " + val, args, nil
	case OpLte:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " <= " + val, args, nil
	case OpContains:
		return prefix + "position(" + c.Field + ", ?) > 0", []any{c.Value}, nil
	case OpStartsWith:
		return prefix + "startsWith(" + c.Field + ", ?)", []any{c.Value}, nil
	case OpEndsWith:
		return prefix + "endsWith(" + c.Field + ", ?)", []any{c.Value}, nil
	case OpMatches:
		return prefix + "match(" + c.Field + ", ?)", []any{c.Value}, nil
	case OpIn:
		items := strings.Split(c.Value, ",")
		placeholders := make([]string, len(items))
		args := make([]any, len(items))
		for i, item := range items {
			placeholders[i] = "?"
			args[i] = strings.TrimSpace(item)
		}
		return prefix + c.Field + " IN (" + strings.Join(placeholders, ", ") + ")", args, nil
	default:
		return "", nil, fmt.Errorf("unsupported operator %d", c.Op)
	}
}

func compileHavingCondition(c Condition) (string, []any, error) {
	// Having conditions reference aliases (stats output names).
	// Don't validate against table fields.
	prefix := ""
	if c.Negate {
		prefix = "NOT "
	}

	switch c.Op {
	case OpEq:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " = " + val, args, nil
	case OpNeq:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " != " + val, args, nil
	case OpGt:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " > " + val, args, nil
	case OpGte:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " >= " + val, args, nil
	case OpLt:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " < " + val, args, nil
	case OpLte:
		val, args := compileValue(c.Value)
		return prefix + c.Field + " <= " + val, args, nil
	default:
		return "", nil, fmt.Errorf("unsupported having operator %d", c.Op)
	}
}

func compileFuncCondition(c Condition) (string, []any, error) {
	prefix := ""
	if c.Negate {
		prefix = "NOT "
	}

	switch c.Function {
	case "is_private_ip":
		// Check if IP is in private ranges.
		return prefix + "(startsWith(" + c.Field + ", '10.') OR startsWith(" + c.Field + ", '192.168.') OR startsWith(" + c.Field + ", '172.'))", nil, nil
	case "is_dns_tunnel":
		// Heuristic: domain length > 50 or high entropy.
		return prefix + "(length(" + c.Field + ") > 50)", nil, nil
	default:
		return "", nil, fmt.Errorf("unknown function %q", c.Function)
	}
}

// compileValue handles special value types like now()-24h.
func compileValue(val string) (string, []any) {
	if strings.HasPrefix(val, "now()") {
		if val == "now()" {
			return "now()", nil
		}
		// now()-24h → now() - INTERVAL 24 HOUR
		rest := strings.TrimPrefix(val, "now()-")
		dur := parseDuration(rest)
		return fmt.Sprintf("now() - INTERVAL %d SECOND", int(dur.Seconds())), nil
	}

	// Try as number.
	if _, err := strconv.ParseFloat(val, 64); err == nil {
		return val, nil
	}

	// String parameter.
	return "?", []any{val}
}

func compileAggFunc(agg Aggregation) (string, error) {
	switch agg.Func {
	case "count":
		return "count()", nil
	case "unique_count", "uniq":
		if agg.Field == "" {
			return "", fmt.Errorf("unique_count requires a field argument")
		}
		if err := validateField(agg.Field); err != nil {
			return "", err
		}
		return "uniqExact(" + agg.Field + ")", nil
	case "min":
		if err := validateField(agg.Field); err != nil {
			return "", err
		}
		return "min(" + agg.Field + ")", nil
	case "max":
		if err := validateField(agg.Field); err != nil {
			return "", err
		}
		return "max(" + agg.Field + ")", nil
	case "avg":
		if err := validateField(agg.Field); err != nil {
			return "", err
		}
		return "avg(toFloat64OrZero(" + agg.Field + "))", nil
	case "sum":
		if err := validateField(agg.Field); err != nil {
			return "", err
		}
		return "sum(toFloat64OrZero(" + agg.Field + "))", nil
	default:
		return "", fmt.Errorf("unknown aggregation function %q", agg.Func)
	}
}

func validateField(field string) error {
	if !validFields[field] {
		return fmt.Errorf("unknown field %q", field)
	}
	return nil
}

func parseDuration(s string) time.Duration {
	if len(s) < 2 {
		return 0
	}
	numStr := s[:len(s)-1]
	unit := s[len(s)-1]
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return 0
	}
	switch unit {
	case 's':
		return time.Duration(n) * time.Second
	case 'm':
		return time.Duration(n) * time.Minute
	case 'h':
		return time.Duration(n) * time.Hour
	case 'd':
		return time.Duration(n) * 24 * time.Hour
	default:
		return 0
	}
}
