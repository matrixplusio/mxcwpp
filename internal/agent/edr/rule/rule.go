// Package rule implements the agent-side YAML rule engine for EDR event detection.
//
// Rules are loaded from YAML files, validated at load time, and indexed by event_type
// for O(1) candidate lookup. The matching engine evaluates conditions with short-circuit
// logic (AND/OR) and pre-compiled regexps.
//
// Architecture: rules define both agent-side lightweight matching and optional
// server-side CEL deep analysis in a single YAML file. This package handles
// agent-side matching only.
package rule

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
)

// CurrentSchemaVersion is the supported rule schema version.
// Future versions can route to different parsing logic (similar to K8s apiVersion).
const CurrentSchemaVersion = 1

// Severity levels ordered by criticality.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ActionType defines what the agent does when a rule matches.
type ActionType string

const (
	ActionAlert      ActionType = "alert"      // Report only, no local action.
	ActionSuspend    ActionType = "suspend"    // SIGSTOP the process, notify admin.
	ActionKill       ActionType = "kill"       // SIGKILL the process.
	ActionQuarantine ActionType = "quarantine" // Move file to isolation directory.
)

// Logic defines how conditions are combined.
type Logic string

const (
	LogicAnd Logic = "and"
	LogicOr  Logic = "or"
)

// Operator defines how a field value is compared.
type Operator string

const (
	OpEquals    Operator = "equals"
	OpNotEquals Operator = "not_equals"
	OpContains  Operator = "contains"
	OpStartsW   Operator = "starts_with"
	OpEndsW     Operator = "ends_with"
	OpRegex     Operator = "regex"
	OpIn        Operator = "in"
	OpGT        Operator = "gt"
	OpLT        Operator = "lt"
	// OpInCIDR / OpNotInCIDR 按网段判断 IP 字段，values 为 CIDR 列表。
	//
	// 补这两个算子的直接原因：网络类规则此前只能匹配端口，无法表达"目的地址在哪"。
	// 于是 c2_high_risk_port / cryptominer_pool_port / c2_tor_proxy 三条规则
	// 退化成"目的端口 ∈ 清单即 C2"，而 这些端口在内网普遍被业务与运维组件占用——
	// 这三条规则的命中全部落在内网、外网零命中，
	// 全量误报，并把 storyline_events 撑到 亿级行、数百 GB 拖垮平台。
	// 真实 C2 必然打外网，加一条 not_in_cidr 私网排除即可清零误报且不损检出。
	OpInCIDR    Operator = "in_cidr"
	OpNotInCIDR Operator = "not_in_cidr"
)

// Rule represents a single detection rule loaded from YAML.
type Rule struct {
	SchemaVersion int      `yaml:"schema_version"`
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	Version       int      `yaml:"version"`
	Category      string   `yaml:"category"` // process | file | network
	Severity      Severity `yaml:"severity"`

	MITRE *MITRERef `yaml:"mitre,omitempty"`
	Tags  []string  `yaml:"tags,omitempty"`

	Agent    AgentMatch `yaml:"agent"`
	Metadata *Metadata  `yaml:"metadata,omitempty"`
}

// MITRERef maps a rule to MITRE ATT&CK framework.
type MITRERef struct {
	Tactic    string `yaml:"tactic"`
	Technique string `yaml:"technique"`
}

// AgentMatch defines the agent-side matching configuration.
type AgentMatch struct {
	Enabled bool       `yaml:"enabled"`
	Action  ActionType `yaml:"action"`
	Enforce bool       `yaml:"enforce"` // false = alert only, true = execute action
	Match   MatchSpec  `yaml:"match"`
}

// MatchSpec defines the event matching criteria.
type MatchSpec struct {
	EventType  string      `yaml:"event_type"`
	Conditions []Condition `yaml:"conditions"`
	Logic      Logic       `yaml:"logic"`
}

// Condition is a single field comparison.
type Condition struct {
	Field string   `yaml:"field"`
	Op    Operator `yaml:"op"`
	Value string   `yaml:"value"`

	// Values is used for "in" operator (list of allowed values).
	Values []string `yaml:"values,omitempty"`

	// compiledRegex is populated at load time for regex operators.
	compiledRegex *regexp.Regexp

	// compiledCIDRs is populated at load time for in_cidr / not_in_cidr operators.
	compiledCIDRs []*net.IPNet

	// cost is the evaluation cost used for condition ordering.
	// Lower cost conditions are evaluated first for short-circuit optimization.
	cost int
}

// Metadata provides human-readable context for a rule.
type Metadata struct {
	Author        string   `yaml:"author,omitempty"`
	Created       string   `yaml:"created,omitempty"`
	Updated       string   `yaml:"updated,omitempty"`
	Description   string   `yaml:"description,omitempty"`
	References    []string `yaml:"references,omitempty"`
	FalsePositive []string `yaml:"false_positive,omitempty"`
	Confidence    int      `yaml:"confidence,omitempty"` // 0-100
}

// validSeverities is the set of allowed severity values.
var validSeverities = map[Severity]bool{
	SeverityInfo: true, SeverityLow: true, SeverityMedium: true,
	SeverityHigh: true, SeverityCritical: true,
}

// validActions is the set of allowed action values.
var validActions = map[ActionType]bool{
	ActionAlert: true, ActionSuspend: true, ActionKill: true, ActionQuarantine: true,
}

// validOperators is the set of allowed operator values.
var validOperators = map[Operator]bool{
	OpEquals: true, OpNotEquals: true, OpContains: true,
	OpStartsW: true, OpEndsW: true, OpRegex: true,
	OpIn: true, OpGT: true, OpLT: true,
	OpInCIDR: true, OpNotInCIDR: true,
}

// validLogic is the set of allowed logic values.
var validLogic = map[Logic]bool{
	LogicAnd: true, LogicOr: true,
}

// operatorCost assigns evaluation cost for condition ordering.
// Lower cost = evaluated first in short-circuit chain.
var operatorCost = map[Operator]int{
	OpEquals:    1,
	OpNotEquals: 1,
	OpIn:        2,
	OpGT:        2,
	OpLT:        2,
	OpContains:  3,
	OpStartsW:   3,
	OpEndsW:     3,
	OpInCIDR:    4, // 需解析 IP 再逐网段比对，比字符串比较贵、比正则便宜。
	OpNotInCIDR: 4,
	OpRegex:     10, // Regex always last.
}

// Validate checks the rule for correctness. Called at load time, not at match time.
// Returns an error describing the first validation failure.
func (r *Rule) Validate() error {
	if r.SchemaVersion == 0 {
		r.SchemaVersion = CurrentSchemaVersion
	}
	if r.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d (expected %d)", r.SchemaVersion, CurrentSchemaVersion)
	}

	if r.ID == "" {
		return fmt.Errorf("rule id is required")
	}
	if r.Name == "" {
		return fmt.Errorf("rule %s: name is required", r.ID)
	}
	if r.Version < 1 {
		return fmt.Errorf("rule %s: version must be >= 1", r.ID)
	}
	if r.Category == "" {
		return fmt.Errorf("rule %s: category is required", r.ID)
	}
	if !validSeverities[r.Severity] {
		return fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
	}

	// Agent match validation.
	if !r.Agent.Enabled {
		return nil // Agent-disabled rules pass validation (server-only rules).
	}

	if r.Agent.Action == "" {
		r.Agent.Action = ActionAlert // Default action.
	}
	if !validActions[r.Agent.Action] {
		return fmt.Errorf("rule %s: invalid action %q", r.ID, r.Agent.Action)
	}

	m := r.Agent.Match
	if m.EventType == "" {
		return fmt.Errorf("rule %s: agent.match.event_type is required", r.ID)
	}
	if len(m.Conditions) == 0 {
		return fmt.Errorf("rule %s: agent.match.conditions must not be empty", r.ID)
	}
	if m.Logic == "" {
		r.Agent.Match.Logic = LogicAnd // Default logic.
	}
	if !validLogic[r.Agent.Match.Logic] {
		return fmt.Errorf("rule %s: invalid logic %q", r.ID, m.Logic)
	}

	for i := range r.Agent.Match.Conditions {
		if err := r.Agent.Match.Conditions[i].validate(r.ID, i); err != nil {
			return err
		}
	}

	return nil
}

// validate checks a single condition and pre-compiles regex.
func (c *Condition) validate(ruleID string, idx int) error {
	if c.Field == "" {
		return fmt.Errorf("rule %s: condition[%d].field is required", ruleID, idx)
	}
	if !validOperators[c.Op] {
		return fmt.Errorf("rule %s: condition[%d] invalid operator %q", ruleID, idx, c.Op)
	}

	switch c.Op {
	case OpIn:
		if len(c.Values) == 0 {
			return fmt.Errorf("rule %s: condition[%d] 'in' operator requires non-empty values list", ruleID, idx)
		}
	case OpInCIDR, OpNotInCIDR:
		if len(c.Values) == 0 {
			return fmt.Errorf("rule %s: condition[%d] %q operator requires non-empty values list", ruleID, idx, c.Op)
		}
		c.compiledCIDRs = make([]*net.IPNet, 0, len(c.Values))
		for _, v := range c.Values {
			_, netw, err := net.ParseCIDR(v)
			if err != nil {
				return fmt.Errorf("rule %s: condition[%d] invalid CIDR %q: %w", ruleID, idx, v, err)
			}
			c.compiledCIDRs = append(c.compiledCIDRs, netw)
		}
	case OpRegex:
		if c.Value == "" {
			return fmt.Errorf("rule %s: condition[%d] regex value is required", ruleID, idx)
		}
		compiled, err := regexp.Compile(c.Value)
		if err != nil {
			return fmt.Errorf("rule %s: condition[%d] invalid regex %q: %w", ruleID, idx, c.Value, err)
		}
		c.compiledRegex = compiled
	default:
		if c.Value == "" && c.Op != OpEquals && c.Op != OpNotEquals {
			return fmt.Errorf("rule %s: condition[%d] value is required for operator %q", ruleID, idx, c.Op)
		}
	}

	// Assign cost for condition ordering.
	c.cost = operatorCost[c.Op]

	return nil
}

// Evaluate checks if the condition matches the given field value.
func (c *Condition) Evaluate(fieldValue string) bool {
	switch c.Op {
	case OpEquals:
		return fieldValue == c.Value
	case OpNotEquals:
		return fieldValue != c.Value
	case OpContains:
		return strings.Contains(fieldValue, c.Value)
	case OpStartsW:
		return strings.HasPrefix(fieldValue, c.Value)
	case OpEndsW:
		return strings.HasSuffix(fieldValue, c.Value)
	case OpRegex:
		if c.compiledRegex == nil {
			return false
		}
		return c.compiledRegex.MatchString(fieldValue)
	case OpIn:
		return slices.Contains(c.Values, fieldValue)
	case OpInCIDR, OpNotInCIDR:
		// 地址解析不出来时一律返回 false（不命中），两个算子都是。
		//
		// not_in_cidr 一侧这是刻意的：它表达的是"确认该地址在给定网段之外"。
		// 字段为空或非法时我们并不掌握这个事实，此时判命中等于把所有采集不到
		// 目的地址的事件都变成告警——正是这类"不知道就报"的判据制造了
		// 2026-08 那批全量误报。宁可漏一条，不可造一片。
		ip := net.ParseIP(fieldValue)
		if ip == nil {
			return false
		}
		inside := cidrsContain(c.compiledCIDRs, ip)
		return (c.Op == OpInCIDR) == inside
	case OpGT:
		return compareNumeric(fieldValue, c.Value) > 0
	case OpLT:
		return compareNumeric(fieldValue, c.Value) < 0
	default:
		return false
	}
}

// cidrsContain 判断 IP 是否落在任一网段内。
//
// 单独成函数而非 Condition 方法：它不依赖 Condition 的任何状态，
// 且 Evaluate 在热路径上（线上日均数千万条网络事件逐条求值），
// 保持一次解析、一次遍历。
func cidrsContain(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// compareNumeric compares two string values as integers.
// Returns -1, 0, or 1. Non-numeric values compare as strings.
func compareNumeric(a, b string) int {
	// Fast path: try integer comparison.
	var ai, bi int
	if _, err := fmt.Sscanf(a, "%d", &ai); err == nil {
		if _, err := fmt.Sscanf(b, "%d", &bi); err == nil {
			switch {
			case ai < bi:
				return -1
			case ai > bi:
				return 1
			default:
				return 0
			}
		}
	}
	// Fallback: string comparison.
	return strings.Compare(a, b)
}
