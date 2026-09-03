// Package mql implements the MxCwpp Query Language compiler.
// MQL is a pipe-delimited query language for threat hunting over ClickHouse events.
//
// Syntax:
//
//	search events
//	| where <condition>
//	| stats <aggregation> by <field>
//	| sort <field> [asc|desc]
//	| limit <n>
package mql

// Query is the root AST node for a parsed MQL query.
type Query struct {
	Source string       // "events" (ebpf_events table)
	Wheres []Condition  // filter conditions
	Stats  *StatsClause // optional aggregation
	Having []Condition  // post-aggregation filter (where after stats)
	Sort   []SortField  // ORDER BY
	Limit  int          // LIMIT (0 = use default)
}

// Condition represents a WHERE/HAVING clause predicate.
type Condition struct {
	Field    string // e.g. "event_type", "cmdline"
	Op       Op     // operator
	Value    string // literal value
	Function string // built-in function name (for function calls like is_private_ip)
	Negate   bool   // NOT prefix
}

// Op is a comparison operator.
type Op int

const (
	OpEq         Op = iota // ==
	OpNeq                  // !=
	OpGt                   // >
	OpGte                  // >=
	OpLt                   // <
	OpLte                  // <=
	OpContains             // contains
	OpStartsWith           // startswith
	OpEndsWith             // endswith
	OpMatches              // matches (regex)
	OpIn                   // in (list)
)

// StatsClause represents an aggregation clause.
type StatsClause struct {
	Aggregations []Aggregation // e.g. count(), unique_count(field)
	GroupBy      []string      // GROUP BY fields
}

// Aggregation is a single stats function call.
type Aggregation struct {
	Func  string // count, unique_count, min, max, avg, sum
	Field string // argument field (empty for count())
	Alias string // AS alias
}

// SortField is a single ORDER BY clause.
type SortField struct {
	Field string
	Desc  bool
}
