//go:build linux

// Package isolate provides host network isolation via iptables.
//
// Three isolation levels:
//   - Selective: block individual IP:port pairs (MXCWPP_BLOCK chain)
//   - Standard: block all traffic except management + DNS (MXCWPP_ISOLATE chain)
//   - Complete: block all traffic except management channel only
//
// Safety measures:
//   - Management channel (Server IP:port) always whitelisted
//   - Timeout-based auto-release (default 4h, configurable)
//   - Audit log of all isolate/release actions
//   - Dedicated chains for clean teardown (MXCWPP_ISOLATE, MXCWPP_BLOCK)
package isolate

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	isolateChain   = "MXCWPP_ISOLATE" // full host isolation chain
	blockChain     = "MXCWPP_BLOCK"   // selective IP blocking chain
	defaultTimeout = 4 * time.Hour
)

// Manager manages host network isolation state.
type Manager struct {
	logger     *zap.Logger
	serverAddr string // Server gRPC address (IP:port) to whitelist
	serverIP   string // extracted IP from serverAddr

	mu        sync.Mutex
	level     Level
	isolateAt time.Time
	timeout   time.Duration
	reason    string
	timer     *time.Timer

	// Selective blocking: active per-IP rules.
	blockRules map[uint]*BlockRule // keyed by RuleID
	blockReady bool                // true if MXCWPP_BLOCK chain is installed
}

// NewManager creates a network isolation manager.
// serverAddr is the Agent->Server gRPC address (e.g., "192.168.1.100:6751").
func NewManager(logger *zap.Logger, serverAddr string) *Manager {
	ip := serverAddr
	if idx := strings.LastIndex(serverAddr, ":"); idx > 0 {
		ip = serverAddr[:idx]
	}

	return &Manager{
		logger:     logger,
		serverAddr: serverAddr,
		serverIP:   ip,
		timeout:    defaultTimeout,
		level:      LevelNone,
		blockRules: make(map[uint]*BlockRule),
	}
}

// --- Full host isolation (Standard / Complete) ---

// Isolate enables network isolation at the given level.
// reason is logged for audit. timeoutSec overrides default timeout (0 = use default).
func (m *Manager) Isolate(reason string, timeoutSec int, level Level) error {
	if level != LevelStandard && level != LevelComplete {
		return fmt.Errorf("invalid isolation level %q, use standard or complete", level)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.level == LevelStandard || m.level == LevelComplete {
		return fmt.Errorf("host already isolated at level %s", m.level)
	}

	allowDNS := level == LevelStandard
	if err := m.setupIsolation(allowDNS); err != nil {
		return fmt.Errorf("setup isolation: %w", err)
	}

	m.level = level
	m.isolateAt = time.Now()
	m.reason = reason

	timeout := m.timeout
	if timeoutSec > 0 {
		timeout = time.Duration(timeoutSec) * time.Second
	}

	// Auto-release timer.
	m.timer = time.AfterFunc(timeout, func() {
		m.logger.Warn("network isolation auto-released (timeout)",
			zap.Duration("duration", timeout))
		if err := m.Release("timeout auto-release"); err != nil {
			m.logger.Error("auto-release failed", zap.Error(err))
		}
	})

	m.logger.Warn("HOST NETWORK ISOLATED",
		zap.String("level", string(level)),
		zap.String("reason", reason),
		zap.String("server_ip", m.serverIP),
		zap.Duration("timeout", timeout))

	return nil
}

// Release removes full host isolation and restores normal connectivity.
func (m *Manager) Release(reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.level != LevelStandard && m.level != LevelComplete {
		return fmt.Errorf("host is not isolated")
	}

	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}

	if err := m.teardownIsolation(); err != nil {
		return fmt.Errorf("teardown isolation: %w", err)
	}

	duration := time.Since(m.isolateAt)
	prevLevel := m.level

	// Restore to selective if block rules exist, otherwise none.
	if len(m.blockRules) > 0 {
		m.level = LevelSelective
	} else {
		m.level = LevelNone
	}
	m.reason = ""

	m.logger.Warn("HOST NETWORK ISOLATION RELEASED",
		zap.String("previous_level", string(prevLevel)),
		zap.String("reason", reason),
		zap.Duration("was_isolated_for", duration))

	return nil
}

// --- Selective IP blocking ---

// BlockIP adds a selective block rule for a specific IP:port.
func (m *Manager) BlockIP(rule BlockRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for duplicate.
	if _, exists := m.blockRules[rule.RuleID]; exists {
		return fmt.Errorf("block rule %d already exists", rule.RuleID)
	}

	// Ensure the MXCWPP_BLOCK chain exists.
	if err := m.ensureBlockChain(); err != nil {
		return fmt.Errorf("ensure block chain: %w", err)
	}

	// Add iptables rule.
	if err := m.addBlockRule(&rule); err != nil {
		return fmt.Errorf("add block rule: %w", err)
	}

	rule.CreatedAt = time.Now()
	m.blockRules[rule.RuleID] = &rule

	if m.level == LevelNone {
		m.level = LevelSelective
	}

	m.logger.Info("selective IP block added",
		zap.Uint("rule_id", rule.RuleID),
		zap.String("ip", rule.IP),
		zap.Int("port", rule.Port),
		zap.String("protocol", rule.Protocol),
		zap.String("direction", rule.Direction))

	return nil
}

// UnblockIP removes a selective block rule by RuleID.
func (m *Manager) UnblockIP(ruleID uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rule, exists := m.blockRules[ruleID]
	if !exists {
		return fmt.Errorf("block rule %d not found", ruleID)
	}

	// Remove iptables rule.
	m.removeBlockRule(rule)
	delete(m.blockRules, ruleID)

	// If no more block rules and not fully isolated, set level to none.
	if len(m.blockRules) == 0 {
		m.teardownBlockChain()
		if m.level == LevelSelective {
			m.level = LevelNone
		}
	}

	m.logger.Info("selective IP block removed",
		zap.Uint("rule_id", ruleID),
		zap.String("ip", rule.IP))

	return nil
}

// --- Status queries ---

// IsIsolated returns true if host is under standard or complete isolation.
func (m *Manager) IsIsolated() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.level == LevelStandard || m.level == LevelComplete
}

// Level returns the current isolation level.
func (m *Manager) GetLevel() Level {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.level
}

// Status returns isolation details.
func (m *Manager) Status() (level Level, reason string, since time.Time, blockCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.level, m.reason, m.isolateAt, len(m.blockRules)
}

// BlockRules returns a snapshot of active block rules.
func (m *Manager) BlockRules() []BlockRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules := make([]BlockRule, 0, len(m.blockRules))
	for _, r := range m.blockRules {
		rules = append(rules, *r)
	}
	return rules
}

// --- iptables operations: full isolation ---

// setupIsolation creates iptables rules to block all traffic except management channel.
func (m *Manager) setupIsolation(allowDNS bool) error {
	commands := [][]string{
		// Create dedicated chain.
		{"iptables", "-N", isolateChain},

		// Allow established/related connections (don't break existing management session).
		{"iptables", "-A", isolateChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},

		// Allow loopback.
		{"iptables", "-A", isolateChain, "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", isolateChain, "-o", "lo", "-j", "ACCEPT"},

		// Allow management channel: Agent <-> Server.
		{"iptables", "-A", isolateChain, "-d", m.serverIP, "-j", "ACCEPT"},
		{"iptables", "-A", isolateChain, "-s", m.serverIP, "-j", "ACCEPT"},
	}

	// Standard level allows DNS; complete does not.
	if allowDNS {
		commands = append(commands,
			[]string{"iptables", "-A", isolateChain, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
			[]string{"iptables", "-A", isolateChain, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
		)
	}

	// Drop everything else.
	commands = append(commands,
		[]string{"iptables", "-A", isolateChain, "-j", "DROP"},

		// Insert chain into INPUT, OUTPUT, FORWARD.
		[]string{"iptables", "-I", "INPUT", "1", "-j", isolateChain},
		[]string{"iptables", "-I", "OUTPUT", "1", "-j", isolateChain},
		[]string{"iptables", "-I", "FORWARD", "1", "-j", isolateChain},
	)

	for _, args := range commands {
		if err := runCmd(args[0], args[1:]...); err != nil {
			// Cleanup on failure.
			_ = m.teardownIsolation()
			return fmt.Errorf("command %v failed: %w", args, err)
		}
	}

	return nil
}

// teardownIsolation removes all isolation iptables rules.
func (m *Manager) teardownIsolation() error {
	// Remove chain references from INPUT/OUTPUT/FORWARD.
	_ = runCmd("iptables", "-D", "INPUT", "-j", isolateChain)
	_ = runCmd("iptables", "-D", "OUTPUT", "-j", isolateChain)
	_ = runCmd("iptables", "-D", "FORWARD", "-j", isolateChain)

	// Flush and delete chain.
	_ = runCmd("iptables", "-F", isolateChain)
	_ = runCmd("iptables", "-X", isolateChain)

	return nil
}

// --- iptables operations: selective blocking ---

// ensureBlockChain creates the MXCWPP_BLOCK chain and inserts it if not already present.
func (m *Manager) ensureBlockChain() error {
	if m.blockReady {
		return nil
	}

	// Create chain (may already exist — ignore error).
	_ = runCmd("iptables", "-N", blockChain)

	// Insert into INPUT/OUTPUT if not already there.
	// We use -C (check) first to avoid duplicate insertions.
	if runCmd("iptables", "-C", "INPUT", "-j", blockChain) != nil {
		if err := runCmd("iptables", "-I", "INPUT", "1", "-j", blockChain); err != nil {
			return err
		}
	}
	if runCmd("iptables", "-C", "OUTPUT", "-j", blockChain) != nil {
		if err := runCmd("iptables", "-I", "OUTPUT", "1", "-j", blockChain); err != nil {
			return err
		}
	}
	if runCmd("iptables", "-C", "FORWARD", "-j", blockChain) != nil {
		if err := runCmd("iptables", "-I", "FORWARD", "1", "-j", blockChain); err != nil {
			return err
		}
	}

	m.blockReady = true
	return nil
}

// teardownBlockChain removes the MXCWPP_BLOCK chain entirely.
func (m *Manager) teardownBlockChain() {
	_ = runCmd("iptables", "-D", "INPUT", "-j", blockChain)
	_ = runCmd("iptables", "-D", "OUTPUT", "-j", blockChain)
	_ = runCmd("iptables", "-D", "FORWARD", "-j", blockChain)
	_ = runCmd("iptables", "-F", blockChain)
	_ = runCmd("iptables", "-X", blockChain)
	m.blockReady = false
}

// addBlockRule adds iptables rules to block a specific IP:port.
func (m *Manager) addBlockRule(rule *BlockRule) error {
	args := m.buildBlockArgs("-A", rule)
	for _, a := range args {
		if err := runCmd("iptables", a...); err != nil {
			return fmt.Errorf("iptables %v: %w", a, err)
		}
	}
	return nil
}

// removeBlockRule removes iptables rules for a specific block entry.
func (m *Manager) removeBlockRule(rule *BlockRule) {
	args := m.buildBlockArgs("-D", rule)
	for _, a := range args {
		_ = runCmd("iptables", a...)
	}
}

// buildBlockArgs constructs iptables arguments for a block rule.
// action is "-A" (append) or "-D" (delete).
func (m *Manager) buildBlockArgs(action string, rule *BlockRule) [][]string {
	proto := rule.Protocol
	if proto == "" {
		proto = "tcp"
	}

	var result [][]string

	base := []string{action, blockChain, "-p", proto}

	// Direction determines src/dst.
	switch rule.Direction {
	case "inbound":
		base = append(base, "-s", rule.IP)
	default: // outbound
		base = append(base, "-d", rule.IP)
	}

	if rule.Port > 0 {
		base = append(base, "--dport", fmt.Sprintf("%d", rule.Port))
	}

	base = append(base, "-j", "DROP")
	result = append(result, base)

	return result
}

func runCmd(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
