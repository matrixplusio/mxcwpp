package rule

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Manager loads, indexes, and manages detection rules.
// Thread-safe: the active rule set is swapped atomically.
type Manager struct {
	logger  *zap.Logger
	ruleDir string

	// rules stores the current active rule set (atomic pointer swap for hot-reload).
	rules atomic.Pointer[RuleSet]

	// previous keeps the last known-good rule set for rollback.
	previous atomic.Pointer[RuleSet]

	// verifyKey is the Ed25519 public key for signature verification (optional).
	// When set, Server-pushed rules must include a valid signature.
	verifyKey ed25519.PublicKey
}

// RuleSet is an immutable snapshot of loaded rules, indexed by event_type.
type RuleSet struct {
	// All holds every loaded rule keyed by rule ID.
	All map[string]*Rule

	// ByEventType indexes agent-enabled rules by their match event_type.
	// Key = event_type string (e.g. "process_exec"), value = rules that match this event.
	ByEventType map[string][]*Rule

	// Version is the rule set version string reported to Server.
	Version string

	// Count is the total number of agent-enabled rules.
	Count int

	// LoadErrors collects validation errors for rules that failed to load.
	LoadErrors []string
}

// NewManager creates a rule manager that loads rules from the given directory.
func NewManager(logger *zap.Logger, ruleDir string) *Manager {
	m := &Manager{
		logger:  logger,
		ruleDir: ruleDir,
	}
	// Initialize with empty rule set.
	m.rules.Store(&RuleSet{
		All:         make(map[string]*Rule),
		ByEventType: make(map[string][]*Rule),
	})
	return m
}

// Load reads all YAML rule files from the rule directory, validates them,
// builds the event_type index, and atomically swaps the active rule set.
//
// Rules that fail validation are skipped (logged + collected in LoadErrors).
// Returns error only if the directory is unreadable.
func (m *Manager) Load() error {
	entries, err := os.ReadDir(m.ruleDir)
	if err != nil {
		return fmt.Errorf("read rule directory %s: %w", m.ruleDir, err)
	}

	all := make(map[string]*Rule)
	index := make(map[string][]*Rule)
	var loadErrors []string
	var agentCount int

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		filePath := filepath.Join(m.ruleDir, entry.Name())
		rule, err := loadRuleFile(filePath)
		if err != nil {
			errMsg := fmt.Sprintf("%s: %v", entry.Name(), err)
			loadErrors = append(loadErrors, errMsg)
			m.logger.Warn("skipping rule file",
				zap.String("file", entry.Name()),
				zap.Error(err),
			)
			continue
		}

		// Duplicate ID check.
		if _, exists := all[rule.ID]; exists {
			errMsg := fmt.Sprintf("%s: duplicate rule ID %s", entry.Name(), rule.ID)
			loadErrors = append(loadErrors, errMsg)
			m.logger.Warn("skipping duplicate rule",
				zap.String("file", entry.Name()),
				zap.String("rule_id", rule.ID),
			)
			continue
		}

		all[rule.ID] = rule

		// Index only agent-enabled rules.
		if rule.Agent.Enabled {
			et := rule.Agent.Match.EventType
			index[et] = append(index[et], rule)
			agentCount++
		}
	}

	// Sort conditions within each rule by cost (cheap first, regex last).
	for _, rules := range index {
		for _, r := range rules {
			sortConditionsByCost(r.Agent.Match.Conditions)
		}
	}

	rs := &RuleSet{
		All:         all,
		ByEventType: index,
		Version:     fmt.Sprintf("%d", len(all)),
		Count:       agentCount,
		LoadErrors:  loadErrors,
	}

	// Preserve current as previous (for rollback), then swap to new.
	current := m.rules.Load()
	if current != nil && current.Count > 0 {
		m.previous.Store(current)
	}
	m.rules.Store(rs)

	m.logger.Info("rules loaded",
		zap.Int("total", len(all)),
		zap.Int("agent_enabled", agentCount),
		zap.Int("errors", len(loadErrors)),
		zap.String("version", rs.Version),
	)

	return nil
}

// LoadFromData loads rules from raw YAML documents (one per entry).
// Used for Server-pushed rule hot-reload. Each entry is a single rule YAML.
// Successfully loaded rules are also persisted to ruleDir for offline use.
func (m *Manager) LoadFromData(version string, rulesYAML [][]byte) error {
	all := make(map[string]*Rule)
	index := make(map[string][]*Rule)
	var loadErrors []string
	var agentCount int

	for i, data := range rulesYAML {
		var r Rule
		if err := yaml.Unmarshal(data, &r); err != nil {
			errMsg := fmt.Sprintf("rule[%d]: parse YAML: %v", i, err)
			loadErrors = append(loadErrors, errMsg)
			m.logger.Warn("skipping pushed rule", zap.Int("index", i), zap.Error(err))
			continue
		}
		if err := r.Validate(); err != nil {
			errMsg := fmt.Sprintf("rule[%d] %s: %v", i, r.ID, err)
			loadErrors = append(loadErrors, errMsg)
			m.logger.Warn("skipping invalid pushed rule", zap.String("id", r.ID), zap.Error(err))
			continue
		}

		if _, exists := all[r.ID]; exists {
			continue
		}
		all[r.ID] = &r

		if r.Agent.Enabled {
			et := r.Agent.Match.EventType
			index[et] = append(index[et], &r)
			agentCount++
		}

		// Persist to disk for offline use.
		filePath := filepath.Join(m.ruleDir, r.ID+".yaml")
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			m.logger.Warn("failed to persist pushed rule",
				zap.String("id", r.ID), zap.Error(err))
		}
	}

	// Sort conditions by cost.
	for _, rules := range index {
		for _, r := range rules {
			sortConditionsByCost(r.Agent.Match.Conditions)
		}
	}

	rs := &RuleSet{
		All:         all,
		ByEventType: index,
		Version:     version,
		Count:       agentCount,
		LoadErrors:  loadErrors,
	}

	current := m.rules.Load()
	if current != nil && current.Count > 0 {
		m.previous.Store(current)
	}
	m.rules.Store(rs)

	m.logger.Info("rules hot-loaded from Server push",
		zap.String("version", version),
		zap.Int("total", len(all)),
		zap.Int("agent_enabled", agentCount),
		zap.Int("errors", len(loadErrors)),
	)

	return nil
}

// Rollback reverts to the previous rule set.
// Returns false if no previous version is available.
func (m *Manager) Rollback() bool {
	prev := m.previous.Load()
	if prev == nil || prev.Count == 0 {
		m.logger.Warn("no previous rule set available for rollback")
		return false
	}

	current := m.rules.Load()
	m.rules.Store(prev)
	m.previous.Store(current) // Allow rolling forward again.

	m.logger.Info("rules rolled back",
		zap.Int("agent_enabled", prev.Count),
		zap.String("version", prev.Version),
	)
	return true
}

// Rules returns the current active rule set.
func (m *Manager) Rules() *RuleSet {
	return m.rules.Load()
}

// Match evaluates an event against all rules indexed for its event_type.
// Returns a list of matching rules (may be empty).
func (m *Manager) Match(eventType string, fields map[string]string) []*Rule {
	rs := m.rules.Load()
	candidates := rs.ByEventType[eventType]
	if len(candidates) == 0 {
		return nil
	}

	var matched []*Rule
	for _, r := range candidates {
		if evaluateRule(r, fields) {
			matched = append(matched, r)
		}
	}
	return matched
}

// evaluateRule checks if all/any conditions match based on the rule's logic.
func evaluateRule(r *Rule, fields map[string]string) bool {
	conditions := r.Agent.Match.Conditions
	logic := r.Agent.Match.Logic

	switch logic {
	case LogicAnd:
		// Short-circuit: first false → stop.
		for i := range conditions {
			fieldValue := fields[conditions[i].Field]
			if !conditions[i].Evaluate(fieldValue) {
				return false
			}
		}
		return true

	case LogicOr:
		// Short-circuit: first true → stop.
		for i := range conditions {
			fieldValue := fields[conditions[i].Field]
			if conditions[i].Evaluate(fieldValue) {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// loadRuleFile reads and validates a single YAML rule file.
func loadRuleFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	var r Rule
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	return &r, nil
}

// SetVerifyKey configures the Ed25519 public key for rule signature verification.
// When set, LoadFromDataSigned rejects payloads with invalid signatures.
func (m *Manager) SetVerifyKey(pubKeyBase64 string) error {
	keyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d", len(keyBytes))
	}
	m.verifyKey = ed25519.PublicKey(keyBytes)
	m.logger.Info("rule signature verification enabled")
	return nil
}

// LoadFromDataSigned loads Server-pushed rules with signature verification.
// payload is the raw YAML bundle, signature is the base64-encoded Ed25519 signature.
// If no verifyKey is configured, falls back to LoadFromData without verification.
func (m *Manager) LoadFromDataSigned(version string, rulesYAML [][]byte, signatureBase64 string) error {
	if m.verifyKey != nil {
		// Build the signed content: concatenate all rule data for verification.
		h := sha256.New()
		h.Write([]byte(version))
		for _, data := range rulesYAML {
			h.Write(data)
		}
		digest := h.Sum(nil)

		sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
		if err != nil {
			return fmt.Errorf("invalid signature encoding: %w", err)
		}

		if !ed25519.Verify(m.verifyKey, digest, sigBytes) {
			m.logger.Warn("rule signature verification FAILED, rejecting rule push",
				zap.String("version", version))
			return fmt.Errorf("rule signature verification failed")
		}

		m.logger.Info("rule signature verified",
			zap.String("version", version))
	}

	return m.LoadFromData(version, rulesYAML)
}

// sortConditionsByCost sorts conditions by evaluation cost (ascending).
// Cheap operations (equals, not_equals) first, expensive (regex) last.
func sortConditionsByCost(conditions []Condition) {
	sort.SliceStable(conditions, func(i, j int) bool {
		return conditions[i].cost < conditions[j].cost
	})
}
