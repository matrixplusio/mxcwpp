// Package hunting — Threat Hunting DSL (SPL-like) (C4).
//
// 给 SOC 分析师写查询用, 借鉴 Splunk SPL 风格管道语法:
//
//	source="alerts" severity="critical" | where host_id="h-1" | stats count by category | sort -count | head 10
//
// 编译流程:
//  1. Lex: 切 token (字符串/数字/操作符/管道符)
//  2. Parse: 构建 AST (Stages: search / where / stats / sort / head / table)
//  3. Compile: 转 SQL (ClickHouse 或 MySQL 后端)
//  4. Exec: 走查询引擎
//
// 当前 PR: 实现 lex + parse + 编译到 SQL (where/sort/head 子集). stats/eval 留后续 PR.
package hunting

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Query 解析后的查询.
type Query struct {
	Source string  // 数据源: alerts / hosts / events / vulnerabilities
	Stages []Stage // 管道阶段
	Raw    string  // 原始 SPL
}

// Stage 单个管道阶段.
type Stage struct {
	Op   string            // search / where / sort / head / table / stats
	Args map[string]string // op-specific 参数
}

// Compile 把 SPL 字符串编译为 Query.
func Compile(spl string) (*Query, error) {
	q := &Query{Raw: spl}
	parts := splitPipes(spl)
	if len(parts) == 0 {
		return nil, errors.New("empty query")
	}
	// 第一段是隐式 search (filter)
	first, err := parseSearch(parts[0])
	if err != nil {
		return nil, fmt.Errorf("stage 0: %w", err)
	}
	q.Source = first.Args["source"]
	if q.Source == "" {
		q.Source = "alerts"
	}
	delete(first.Args, "source")
	q.Stages = append(q.Stages, first)
	for i, p := range parts[1:] {
		s, err := parseStage(p)
		if err != nil {
			return nil, fmt.Errorf("stage %d: %w", i+1, err)
		}
		q.Stages = append(q.Stages, s)
	}
	return q, nil
}

// splitPipes 按 | 切, 尊重引号内.
func splitPipes(s string) []string {
	var out []string
	var cur strings.Builder
	inStr := false
	var strQ rune
	for _, r := range s {
		if inStr {
			cur.WriteRune(r)
			if r == strQ {
				inStr = false
			}
			continue
		}
		switch r {
		case '"', '\'':
			inStr = true
			strQ = r
			cur.WriteRune(r)
		case '|':
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// parseSearch 第一段: K=V 列表.
func parseSearch(s string) (Stage, error) {
	stage := Stage{Op: "search", Args: map[string]string{}}
	kvs := splitKVs(s)
	for _, kv := range kvs {
		k, v, ok := splitKV(kv)
		if !ok {
			return stage, fmt.Errorf("invalid search clause: %q", kv)
		}
		stage.Args[k] = v
	}
	return stage, nil
}

// parseStage 后续段: <op> [args...]
func parseStage(s string) (Stage, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Stage{}, errors.New("empty stage")
	}
	idx := strings.IndexFunc(s, unicode.IsSpace)
	op := s
	rest := ""
	if idx > 0 {
		op = s[:idx]
		rest = strings.TrimSpace(s[idx+1:])
	}
	stage := Stage{Op: strings.ToLower(op), Args: map[string]string{}}
	switch stage.Op {
	case "where":
		// where field op value (op ∈ =, !=, >, <, >=, <=, contains)
		stage.Args["expr"] = rest
	case "sort":
		// sort -count or sort field
		stage.Args["by"] = rest
	case "head":
		stage.Args["limit"] = rest
	case "table":
		stage.Args["cols"] = rest
	case "stats":
		// stats count by category → count|by=category
		stage.Args["expr"] = rest
	default:
		return stage, fmt.Errorf("unsupported op: %s", op)
	}
	return stage, nil
}

func splitKVs(s string) []string {
	var out []string
	var cur strings.Builder
	inStr := false
	var strQ rune
	for _, r := range s {
		if inStr {
			cur.WriteRune(r)
			if r == strQ {
				inStr = false
			}
			continue
		}
		switch r {
		case '"', '\'':
			inStr = true
			strQ = r
			cur.WriteRune(r)
		case ' ', '\t':
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

func splitKV(s string) (k, v string, ok bool) {
	idx := strings.Index(s, "=")
	if idx <= 0 {
		return "", "", false
	}
	k = strings.TrimSpace(s[:idx])
	v = strings.TrimSpace(s[idx+1:])
	v = strings.Trim(v, "\"'")
	return k, v, true
}

// SQL 把 Query 编译成 SQL 字符串 + 参数列表 (PreparedStatement).
//
// 简化版: 仅支持 where / sort / head, 不支持 stats / eval.
func (q *Query) SQL(maxRows int) (string, []any, error) {
	tbl := q.Source
	if !validIdent(tbl) {
		return "", nil, fmt.Errorf("invalid source: %s", tbl)
	}
	sb := strings.Builder{}
	args := []any{}
	sb.WriteString("SELECT * FROM ")
	sb.WriteString(tbl)

	var conditions []string
	var orderBy string
	limit := maxRows
	if limit <= 0 {
		limit = 200
	}

	for _, st := range q.Stages {
		switch st.Op {
		case "search":
			for k, v := range st.Args {
				if !validIdent(k) {
					return "", nil, fmt.Errorf("invalid field: %s", k)
				}
				conditions = append(conditions, k+" = ?")
				args = append(args, v)
			}
		case "where":
			// 简化解析: field op value
			f, op, val, ok := parseWhereExpr(st.Args["expr"])
			if !ok {
				return "", nil, fmt.Errorf("invalid where: %s", st.Args["expr"])
			}
			if !validIdent(f) {
				return "", nil, fmt.Errorf("invalid field: %s", f)
			}
			switch op {
			case "=", "!=", ">", "<", ">=", "<=":
				conditions = append(conditions, f+" "+op+" ?")
				args = append(args, val)
			case "contains":
				conditions = append(conditions, f+" LIKE ?")
				args = append(args, "%"+val+"%")
			default:
				return "", nil, fmt.Errorf("unsupported op: %s", op)
			}
		case "sort":
			by := strings.TrimSpace(st.Args["by"])
			desc := strings.HasPrefix(by, "-")
			by = strings.TrimPrefix(by, "-")
			by = strings.TrimPrefix(by, "+")
			if !validIdent(by) {
				return "", nil, fmt.Errorf("invalid sort field: %s", by)
			}
			orderBy = by
			if desc {
				orderBy += " DESC"
			} else {
				orderBy += " ASC"
			}
		case "head":
			n, err := atoi(st.Args["limit"])
			if err != nil || n <= 0 {
				return "", nil, fmt.Errorf("invalid head: %s", st.Args["limit"])
			}
			if n < limit {
				limit = n
			}
		}
	}

	if len(conditions) > 0 {
		sb.WriteString(" WHERE ")
		sb.WriteString(strings.Join(conditions, " AND "))
	}
	if orderBy != "" {
		sb.WriteString(" ORDER BY ")
		sb.WriteString(orderBy)
	}
	sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
	return sb.String(), args, nil
}

// parseWhereExpr "host_id = h-1" → ("host_id", "=", "h-1", true).
func parseWhereExpr(s string) (field, op, val string, ok bool) {
	for _, candidate := range []string{">=", "<=", "!=", "=", ">", "<"} {
		if idx := strings.Index(s, candidate); idx > 0 {
			return strings.TrimSpace(s[:idx]),
				candidate,
				strings.Trim(strings.TrimSpace(s[idx+len(candidate):]), "\"'"),
				true
		}
	}
	// contains
	if idx := strings.Index(s, " contains "); idx > 0 {
		return strings.TrimSpace(s[:idx]),
			"contains",
			strings.Trim(strings.TrimSpace(s[idx+len(" contains "):]), "\"'"),
			true
	}
	return "", "", "", false
}

func validIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_') {
			return false
		}
	}
	return true
}

func atoi(s string) (int, error) {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not int: %s", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}
