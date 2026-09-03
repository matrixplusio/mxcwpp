//go:build linux

// Package edr implements the built-in EDR engine for the MxCwpp Agent.
//
// The engine runs in the same process as the Agent (single-process architecture),
// collecting kernel/userspace events and forwarding them to the Server via the
// existing gRPC transport layer.
//
// Architecture decision: EDR is not a plugin. Single process = zero IPC overhead
// on the hot path, unified resource management, and simpler self-protection.
// Scanner and Baseline remain as separate plugin processes.
package edr

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	agentrules "github.com/matrixplusio/mxcwpp/configs/agent-rules"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/bde"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/collector"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/container"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/ioc"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/isolate"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/memfd"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/rule"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/storyline"
	edryara "github.com/matrixplusio/mxcwpp/internal/agent/edr/yara"
	"github.com/matrixplusio/mxcwpp/internal/agent/transport"
)

// Task DataType constants for Server→Agent push (registered in docs/datatype-allocation.md).
const (
	iocTaskDataType     = int32(9300) // IOC data push
	ruleTaskDataType    = int32(9400) // Detection rule push
	networkCmdDataType  = int32(9997) // Network block/isolate command
	responseCmdDataType = int32(9998) // Auto-response command (kill/quarantine)
)

// Engine is the core EDR engine that manages the event collection pipeline.
type Engine struct {
	logger            *zap.Logger
	transport         *transport.Manager
	collector         collector.Collector
	ruleMgr           *rule.Manager
	actionExec        *rule.ActionExecutor
	auditLog          *rule.AuditLogger
	selfProtect       *SelfProtect
	iocStore          *ioc.Store
	yaraScanner       *edryara.Scanner
	yaraEventCh       chan *event.Event
	memfdScanner      *memfd.Scanner
	memfdEventCh      chan *event.Event
	isolateMgr        *isolate.Manager
	containerResolver *container.Resolver
	bdeProfiler       *bde.Profiler
	storyTracker      *storyline.Tracker
	aggregator        *eventAggregator
	taskCh            <-chan *grpcProto.Task
	wg                sync.WaitGroup

	// Pipeline counters for monitoring and heartbeat reporting.
	eventsForwarded atomic.Uint64
	eventsDropped   atomic.Uint64
	rulesMatched    atomic.Uint64
	iocMatched      atomic.Uint64
	yaraScanned     atomic.Uint64
	yaraMatched     atomic.Uint64
	memfdThreats    atomic.Uint64
}

// DefaultRuleDir is the default rule directory on Linux agents.
const DefaultRuleDir = "/var/lib/mxcwpp/rules"

// NewEngine creates a new EDR engine.
// It auto-detects the best collector mode (eBPF or userspace) for the running kernel.
// ruleDir is the directory containing YAML rule files; empty string uses DefaultRuleDir.
// serverAddr is the Server gRPC address for isolation whitelist (e.g., "10.0.0.1:6751").
func NewEngine(logger *zap.Logger, transportMgr *transport.Manager, ruleDir string, serverAddr string) (*Engine, error) {
	coll, err := collector.DetectAndCreate(logger)
	if err != nil {
		return nil, err
	}

	if ruleDir == "" {
		ruleDir = DefaultRuleDir
	}

	// Ensure rule directory exists so rule manager can load files later.
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		logger.Warn("failed to create rule directory", zap.String("path", ruleDir), zap.Error(err))
	}

	// Install built-in rules on first run (don't overwrite existing).
	installBuiltinRules(logger, ruleDir)

	rm := rule.NewManager(logger.Named("rule"), ruleDir)
	if err := rm.Load(); err != nil {
		// Rule loading failure is non-fatal — engine still collects events.
		logger.Warn("failed to load rules, running without rule engine",
			zap.String("rule_dir", ruleDir),
			zap.Error(err),
		)
	}

	// Initialize audit logger and action executor.
	auditLog, err := rule.NewAuditLogger(logger.Named("audit"), "")
	if err != nil {
		logger.Warn("failed to create audit logger, response actions disabled",
			zap.Error(err),
		)
	}

	var actionExec *rule.ActionExecutor
	if auditLog != nil {
		actionExec = rule.NewActionExecutor(logger.Named("action"), auditLog, "")
	}

	logger.Info("EDR engine initialized",
		zap.String("collector_mode", string(coll.Mode())),
		zap.Any("capabilities", coll.Capabilities()),
		zap.Int("rules_loaded", rm.Rules().Count),
	)

	// Initialize IOC store and register task channel for IOC data delivery.
	iocStore := ioc.NewStore(logger.Named("ioc"))
	taskCh := transportMgr.RegisterTaskChannel("edr")

	// Initialize YARA scanner (nil if yr binary or rules not available).
	yaraEventCh := make(chan *event.Event, 64)
	yaraScanner := edryara.NewScanner(logger.Named("yara"), yaraEventCh)

	// Initialize memory threat scanner (nil if /proc not available).
	memfdEventCh := make(chan *event.Event, 64)
	memfdScanner := memfd.NewScanner(logger.Named("memfd"), memfdEventCh)

	// Initialize container metadata resolver (auto-detects runtime).
	containerRes := container.NewResolver(logger.Named("container"))

	// Initialize network isolation manager.
	isoMgr := isolate.NewManager(logger.Named("isolate"), serverAddr)

	return &Engine{
		logger:            logger,
		transport:         transportMgr,
		collector:         coll,
		ruleMgr:           rm,
		actionExec:        actionExec,
		auditLog:          auditLog,
		selfProtect:       NewSelfProtect(logger.Named("selfprotect")),
		iocStore:          iocStore,
		yaraScanner:       yaraScanner,
		yaraEventCh:       yaraEventCh,
		memfdScanner:      memfdScanner,
		memfdEventCh:      memfdEventCh,
		isolateMgr:        isoMgr,
		containerResolver: containerRes,
		bdeProfiler:       bde.NewProfiler(logger.Named("bde")),
		storyTracker:      storyline.NewTracker(logger.Named("storyline")),
		aggregator:        newEventAggregator(logger.Named("aggregator")),
		taskCh:            taskCh,
	}, nil
}

// Start begins event collection, rule matching, and self-protection.
func (e *Engine) Start(ctx context.Context) error {
	eventCh, err := e.collector.Start(ctx)
	if err != nil {
		return err
	}

	// Start self-protection (systemd notify + chattr).
	e.selfProtect.Start(ctx, &e.wg)

	// Start YARA scanner (if available).
	if e.yaraScanner != nil {
		e.yaraScanner.Start(ctx, &e.wg)
	}

	// Start memory threat scanner (if available).
	if e.memfdScanner != nil {
		e.memfdScanner.Start(ctx, &e.wg)
	}

	e.wg.Add(5)
	go e.forwardEvents(ctx, eventCh)
	go e.processTaskLoop(ctx)
	go e.containerCleanupLoop(ctx)
	go e.bdeSnapshotLoop(ctx)
	go e.storyCleanupLoop(ctx)

	e.logger.Info("EDR engine started",
		zap.Bool("yara_available", e.yaraScanner != nil),
		zap.Bool("memfd_scanner", e.memfdScanner != nil),
		zap.String("container_runtime", e.containerResolver.Runtime()))
	return nil
}

// Stop gracefully shuts down the EDR engine.
func (e *Engine) Stop() error {
	e.selfProtect.Stop()
	err := e.collector.Stop()
	e.wg.Wait()
	if e.auditLog != nil {
		_ = e.auditLog.Close()
	}
	e.logger.Info("EDR engine stopped")
	return err
}

// Mode returns the current collector mode (for heartbeat reporting).
func (e *Engine) Mode() collector.Mode {
	return e.collector.Mode()
}

// Capabilities returns the current collector capabilities (for heartbeat reporting).
func (e *Engine) Capabilities() []collector.Capability {
	return e.collector.Capabilities()
}

// HookType returns the BPF hook mechanism detected (for heartbeat reporting).
func (e *Engine) HookType() collector.HookType {
	return e.collector.HookType()
}

// Stats returns cumulative event pipeline counters (forwarded, dropped).
func (e *Engine) Stats() (forwarded, dropped uint64) {
	return e.eventsForwarded.Load(), e.eventsDropped.Load()
}

// DegradationLevel returns the current dynamic degradation level.
func (e *Engine) DegradationLevel() int32 {
	return e.collector.DegradationLevel()
}

// GetEDRMode implements heartbeat.EDRStatusGetter.
func (e *Engine) GetEDRMode() string {
	return string(e.collector.Mode())
}

// GetEDRCapabilities implements heartbeat.EDRStatusGetter.
func (e *Engine) GetEDRCapabilities() []string {
	caps := e.collector.Capabilities()
	result := make([]string, len(caps))
	for i, c := range caps {
		result[i] = string(c)
	}
	return result
}

// GetEDRHookType implements heartbeat.EDRStatusGetter.
func (e *Engine) GetEDRHookType() string {
	return string(e.collector.HookType())
}

// GetEDRStats implements heartbeat.EDRStatusGetter.
func (e *Engine) GetEDRStats() (forwarded, dropped uint64) {
	return e.eventsForwarded.Load(), e.eventsDropped.Load()
}

// RulesVersion returns the current rule set version for heartbeat reporting.
func (e *Engine) RulesVersion() string {
	return e.ruleMgr.Rules().Version
}

// RulesCount returns the number of loaded agent-enabled rules.
func (e *Engine) RulesCount() int {
	return e.ruleMgr.Rules().Count
}

// RulesMatched returns the cumulative count of rule match events.
func (e *Engine) RulesMatched() uint64 {
	return e.rulesMatched.Load()
}

// ReloadRules reloads rules from the rule directory. Thread-safe.
func (e *Engine) ReloadRules() error {
	return e.ruleMgr.Load()
}

// YARAAvailable returns whether the YARA scanner is active.
func (e *Engine) YARAAvailable() bool {
	return e.yaraScanner != nil
}

// YARAStats returns YARA scan counters (scanned, matched).
func (e *Engine) YARAStats() (scanned, matched uint64) {
	return e.yaraScanned.Load(), e.yaraMatched.Load()
}

// MemfdAvailable returns whether the memory threat scanner is active.
func (e *Engine) MemfdAvailable() bool {
	return e.memfdScanner != nil
}

// MemfdStats returns memory threat scan counters (scans, threats).
func (e *Engine) MemfdStats() (scans, threats uint64) {
	if e.memfdScanner == nil {
		return 0, 0
	}
	return e.memfdScanner.Stats()
}

// IsolationLevel returns the current network isolation level.
func (e *Engine) IsolationLevel() string {
	return string(e.isolateMgr.GetLevel())
}

// IsolationStatus returns full isolation state for heartbeat/status reporting.
func (e *Engine) IsolationStatus() (level string, reason string, blockCount int) {
	l, r, _, bc := e.isolateMgr.Status()
	return string(l), r, bc
}

// SelfProtectManager returns the self-protection manager for use by other
// modules (e.g., updater needs to temporarily unlock file immutability
// before installing packages).
func (e *Engine) SelfProtectManager() *SelfProtect {
	return e.selfProtect
}

// forwardEvents reads events from the collector channel, evaluates rules,
// annotates matching events, and sends them through the transport layer.
// High-frequency duplicate events are aggregated in a 10s window before forwarding.
func (e *Engine) forwardEvents(ctx context.Context, eventCh <-chan *event.Event) {
	defer e.wg.Done()

	const sourceName = "edr"

	// Flush aggregation buffer periodically.
	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining aggregated events on shutdown.
			for _, evt := range e.aggregator.FlushAll() {
				e.sendEvent(sourceName, evt)
			}
			return

		case <-flushTicker.C:
			for _, evt := range e.aggregator.Flush() {
				e.sendEvent(sourceName, evt)
			}

		case yaraEvt := <-e.yaraEventCh:
			// YARA detection events bypass aggregation — always forward.
			e.yaraMatched.Add(1)
			e.sendEvent(sourceName, yaraEvt)

		case memfdEvt := <-e.memfdEventCh:
			// Memory threat events bypass aggregation — always forward.
			e.memfdThreats.Add(1)
			e.sendEvent(sourceName, memfdEvt)

		case evt, ok := <-eventCh:
			if !ok {
				for _, remaining := range e.aggregator.FlushAll() {
					e.sendEvent(sourceName, remaining)
				}
				return
			}

			// Container enrichment: resolve PID to container metadata.
			e.enrichContainer(evt)

			// Storyline: inherit story_id from parent on process_exec.
			e.inheritStory(evt)

			// BDE profiling: feed event to behavior profiler.
			e.feedBDE(evt)

			// Rule matching: evaluate all rules indexed for this event type.
			e.evaluateRules(evt)

			// IOC collision: check network events against threat intelligence.
			e.checkIOC(evt)

			// YARA scan: trigger scan for suspicious executables.
			// Pre-block mode: SIGSTOP process before scanning.
			if e.yaraScanner != nil && e.yaraScanner.ShouldScan(evt) {
				e.yaraScanned.Add(1)
				exe := evt.Fields["exe"]
				if e.yaraScanner.PreBlockEnabled() {
					pid, _ := strconv.Atoi(evt.Fields["pid"])
					e.yaraScanner.EnqueuePreBlock(exe, pid, evt.Fields)
				} else {
					e.yaraScanner.Enqueue(exe, evt.Fields)
				}
			}

			// Storyline: annotate event with story_id if tracked.
			e.annotateStory(evt)

			// Aggregation: merge high-frequency duplicate events.
			// Security events (rule/IOC match) bypass aggregation.
			if e.aggregator.TryAggregate(evt) {
				// Event buffered — will be flushed as aggregated summary.
				continue
			}

			e.sendEvent(sourceName, evt)
		}
	}
}

// sendEvent converts an event to a record and sends it via the transport layer.
func (e *Engine) sendEvent(source string, evt *event.Event) {
	record := evt.ToRecord()
	if err := e.transport.SendPluginData(source, record); err != nil {
		e.eventsDropped.Add(1)
		e.logger.Warn("failed to send EDR event",
			zap.String("event_type", string(evt.EventType)),
			zap.Error(err),
		)
	} else {
		e.eventsForwarded.Add(1)
	}
}

// evaluateRules runs the rule engine against an event.
// If rules match, the event Fields are annotated with match metadata.
// Server-side CEL can use these annotations for deeper analysis.
func (e *Engine) evaluateRules(evt *event.Event) {
	matched := e.ruleMgr.Match(string(evt.EventType), evt.Fields)
	if len(matched) == 0 {
		return
	}

	e.rulesMatched.Add(uint64(len(matched)))

	// Annotate event with first (highest severity) match.
	// Multiple matches are joined in agent_rule_ids for Server correlation.
	best := matched[0]
	for _, r := range matched[1:] {
		if severityRank(r.Severity) > severityRank(best.Severity) {
			best = r
		}
	}

	evt.SetField("agent_match", "true")
	evt.SetField("agent_rule_id", best.ID)
	evt.SetField("agent_rule_name", best.Name)
	evt.SetField("agent_severity", string(best.Severity))
	evt.SetField("agent_action", string(best.Agent.Action))
	evt.SetField("agent_enforce", boolStr(best.Agent.Enforce))

	if len(matched) > 1 {
		ids := make([]string, len(matched))
		for i, r := range matched {
			ids[i] = r.ID
		}
		evt.SetField("agent_rule_ids", strings.Join(ids, ","))
	}

	if best.MITRE != nil {
		evt.SetField("agent_mitre_tactic", best.MITRE.Tactic)
		evt.SetField("agent_mitre_technique", best.MITRE.Technique)
	}

	// Storyline: assign story_id to the matching PID.
	if pidStr := evt.Fields["pid"]; pidStr != "" {
		if pid, err := strconv.ParseInt(pidStr, 10, 32); err == nil {
			storyID := e.storyTracker.Assign(int32(pid))
			evt.SetField("story_id", storyID)
		}
	}

	// Execute response actions for all matching rules.
	if e.actionExec != nil {
		for _, r := range matched {
			if r.Agent.Action != rule.ActionAlert {
				e.actionExec.Execute(r, evt.Fields)
			}
		}
	}
}

// severityRank returns numeric rank for severity comparison.
func severityRank(s rule.Severity) int {
	switch s {
	case rule.SeverityInfo:
		return 0
	case rule.SeverityLow:
		return 1
	case rule.SeverityMedium:
		return 2
	case rule.SeverityHigh:
		return 3
	case rule.SeverityCritical:
		return 4
	default:
		return -1
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// IOCVersion returns the current IOC store version for heartbeat reporting.
func (e *Engine) IOCVersion() string {
	return e.iocStore.Version()
}

// IOCCount returns the total number of loaded IOC entries.
func (e *Engine) IOCCount() int {
	return e.iocStore.Count()
}

// IOCMatched returns the cumulative count of IOC match events.
func (e *Engine) IOCMatched() uint64 {
	return e.iocMatched.Load()
}

// processTaskLoop listens for tasks dispatched to the "edr" channel
// and handles IOC data delivery (DataType 9100).
func (e *Engine) processTaskLoop(ctx context.Context) {
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-e.taskCh:
			if !ok {
				return
			}
			e.handleTask(task)
		}
	}
}

// handleTask processes a single task delivered to the EDR engine.
func (e *Engine) handleTask(task *grpcProto.Task) {
	switch task.DataType {
	case iocTaskDataType:
		if err := e.iocStore.Load(task.Data); err != nil {
			e.logger.Warn("failed to load IOC data",
				zap.Error(err),
				zap.Int("data_len", len(task.Data)),
			)
		}
	case ruleTaskDataType:
		e.handleRulePush(task.Data)
	case networkCmdDataType:
		e.handleNetworkCommand(task.Data)
	case responseCmdDataType:
		e.handleResponseCommand(task.Data)
	default:
		e.logger.Debug("ignoring unknown EDR task",
			zap.Int32("data_type", task.DataType),
		)
	}
}

// networkCommandPayload is the JSON envelope for network block/isolate commands.
type networkCommandPayload struct {
	Action    string `json:"action"`    // block_ip, unblock_ip, isolate, release
	IP        string `json:"ip"`        // target IP (for block_ip/unblock_ip)
	Port      int    `json:"port"`      // target port (0 = all)
	Protocol  string `json:"protocol"`  // tcp/udp
	Direction string `json:"direction"` // inbound/outbound
	RuleID    uint   `json:"rule_id"`   // Server-side rule ID
	Level     string `json:"level"`     // standard/complete (for isolate)
	Reason    string `json:"reason"`    // audit reason
	Timeout   int    `json:"timeout"`   // timeout in seconds (for isolate)
}

// handleNetworkCommand processes DataType 9997 network block/isolation commands.
func (e *Engine) handleNetworkCommand(data string) {
	var cmd networkCommandPayload
	if err := json.Unmarshal([]byte(data), &cmd); err != nil {
		e.logger.Warn("failed to parse network command", zap.Error(err))
		return
	}

	var err error
	switch cmd.Action {
	case "block_ip":
		err = e.isolateMgr.BlockIP(isolate.BlockRule{
			RuleID:    cmd.RuleID,
			IP:        cmd.IP,
			Port:      cmd.Port,
			Protocol:  cmd.Protocol,
			Direction: cmd.Direction,
		})
	case "unblock_ip":
		err = e.isolateMgr.UnblockIP(cmd.RuleID)
	case "isolate":
		level := isolate.LevelStandard
		if cmd.Level == "complete" {
			level = isolate.LevelComplete
		}
		reason := cmd.Reason
		if reason == "" {
			reason = "server command"
		}
		err = e.isolateMgr.Isolate(reason, cmd.Timeout, level)
	case "release":
		reason := cmd.Reason
		if reason == "" {
			reason = "server command"
		}
		err = e.isolateMgr.Release(reason)
	default:
		e.logger.Warn("unknown network command action", zap.String("action", cmd.Action))
		return
	}

	if err != nil {
		e.logger.Error("network command failed",
			zap.String("action", cmd.Action),
			zap.Error(err))
	} else {
		e.logger.Info("network command executed",
			zap.String("action", cmd.Action),
			zap.String("ip", cmd.IP),
			zap.String("level", cmd.Level))
	}
}

// responseCommandPayload is the JSON envelope for auto-response commands (DataType 9998).
type responseCommandPayload struct {
	Action  string `json:"action"`  // kill_process, quarantine_file
	Target  string `json:"target"`  // PID or file path
	Trigger string `json:"trigger"` // auto_response, manual
}

// handleResponseCommand processes DataType 9998 auto-response commands.
func (e *Engine) handleResponseCommand(data string) {
	var cmd responseCommandPayload
	if err := json.Unmarshal([]byte(data), &cmd); err != nil {
		e.logger.Warn("failed to parse response command", zap.Error(err))
		return
	}

	e.logger.Info("response command received",
		zap.String("action", cmd.Action),
		zap.String("target", cmd.Target),
		zap.String("trigger", cmd.Trigger))

	// Response commands (kill/quarantine) are handled by the rule engine's ActionExecutor.
	// Construct a synthetic rule for the executor.
	if e.actionExec == nil {
		e.logger.Warn("response command skipped: action executor not initialized")
		return
	}

	fields := map[string]string{"trigger": cmd.Trigger}

	switch cmd.Action {
	case "kill_process":
		fields["pid"] = cmd.Target
		e.actionExec.Execute(&rule.Rule{
			ID:       "remote_kill",
			Name:     "Remote Kill Command",
			Severity: rule.SeverityCritical,
			Agent: rule.AgentMatch{
				Action:  rule.ActionKill,
				Enforce: true,
			},
		}, fields)
	case "quarantine_file":
		fields["file_path"] = cmd.Target
		e.actionExec.Execute(&rule.Rule{
			ID:       "remote_quarantine",
			Name:     "Remote Quarantine Command",
			Severity: rule.SeverityCritical,
			Agent: rule.AgentMatch{
				Action:  rule.ActionQuarantine,
				Enforce: true,
			},
		}, fields)
	default:
		e.logger.Warn("unknown response command action", zap.String("action", cmd.Action))
	}
}

// rulePushPayload is the JSON envelope for Server-pushed rule data.
type rulePushPayload struct {
	Version   string   `json:"version"`
	Rules     []string `json:"rules"`     // Each entry is a YAML rule document.
	Signature string   `json:"signature"` // Ed25519 signature (base64), optional.
}

// handleRulePush processes a Server-pushed rule update.
func (e *Engine) handleRulePush(data string) {
	var payload rulePushPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		e.logger.Warn("failed to parse rule push payload", zap.Error(err))
		return
	}

	rulesData := make([][]byte, len(payload.Rules))
	for i, r := range payload.Rules {
		rulesData[i] = []byte(r)
	}

	var err error
	if payload.Signature != "" {
		err = e.ruleMgr.LoadFromDataSigned(payload.Version, rulesData, payload.Signature)
	} else {
		err = e.ruleMgr.LoadFromData(payload.Version, rulesData)
	}
	if err != nil {
		e.logger.Warn("failed to hot-load rules", zap.Error(err))
		return
	}

	e.logger.Info("rules hot-loaded from Server",
		zap.String("version", payload.Version),
		zap.Int("rules_count", len(payload.Rules)),
		zap.Bool("signed", payload.Signature != ""),
	)
}

// checkIOC checks event fields against the IOC store (IP, Hash, URL).
func (e *Engine) checkIOC(evt *event.Event) {
	// IP check: network events (DataType 3002).
	if evt.DataType == event.DataTypeNetwork {
		if addr := evt.Fields["remote_addr"]; addr != "" && e.iocStore.CheckIP(addr) {
			e.markIOCHit(evt, "ip", addr)
			return
		}
	}

	// Hash check: process events with exe_hash field.
	if evt.DataType == event.DataTypeProcess {
		if hash := evt.Fields["exe_hash"]; hash != "" && e.iocStore.CheckHash(hash) {
			e.markIOCHit(evt, "hash", hash)
			return
		}
	}

	// URL check: any event carrying a url field (e.g. DNS query, HTTP log).
	if url := evt.Fields["url"]; url != "" && e.iocStore.CheckURL(url) {
		e.markIOCHit(evt, "url", url)
	}
}

// markIOCHit annotates an event as IOC-matched and logs the hit.
func (e *Engine) markIOCHit(evt *event.Event, iocType, iocValue string) {
	e.iocMatched.Add(1)

	evt.SetField("ioc_match", "true")
	evt.SetField("ioc_type", iocType)
	evt.SetField("ioc_value", iocValue)

	e.logger.Warn("IOC hit detected",
		zap.String("ioc_type", iocType),
		zap.String("ioc_value", iocValue),
		zap.String("event_type", string(evt.EventType)),
		zap.String("pid", evt.Fields["pid"]),
	)
}

// enrichContainer resolves container metadata for the event's PID
// and annotates the event with container_id, container_name, container_image,
// and K8s context (pod_name, pod_namespace) when applicable.
func (e *Engine) enrichContainer(evt *event.Event) {
	pidStr := evt.Fields["pid"]
	if pidStr == "" {
		return
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return
	}

	info := e.containerResolver.Resolve(pid)
	if info == nil {
		return
	}

	evt.SetField("container_id", info.ContainerID)
	if info.Name != "" {
		evt.SetField("container_name", info.Name)
	}
	if info.Image != "" {
		evt.SetField("container_image", info.Image)
	}
	evt.SetField("container_runtime", info.Runtime)

	// K8s context.
	if info.PodName != "" {
		evt.SetField("pod_name", info.PodName)
		evt.SetField("pod_namespace", info.Namespace)
		evt.SetField("pod_uid", info.PodUID)
	}
}

// containerCleanupLoop periodically removes expired container cache entries.
func (e *Engine) containerCleanupLoop(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed := e.containerResolver.Cleanup()
			if removed > 0 {
				e.logger.Debug("container cache cleanup",
					zap.Int("removed", removed),
					zap.Int("remaining", e.containerResolver.Stats()))
			}
		}
	}
}

// ContainerRuntime returns the detected container runtime name for heartbeat.
func (e *Engine) ContainerRuntime() string {
	return e.containerResolver.Runtime()
}

// feedBDE feeds an event to the BDE profiler for behavior profiling.
func (e *Engine) feedBDE(evt *event.Event) {
	switch evt.DataType {
	case event.DataTypeProcess:
		if evt.EventType == event.ProcessExec {
			e.bdeProfiler.ObserveProcessExec(evt.Fields["exe"])
		}
	case event.DataTypeFile:
		if evt.EventType == event.FileWrite {
			path := evt.Fields["file_path"]
			e.bdeProfiler.ObserveFileWrite(path, bde.IsSensitivePath(path))
		}
	case event.DataTypeNetwork:
		if evt.EventType == event.TCPConnect {
			ip := evt.Fields["remote_addr"]
			e.bdeProfiler.ObserveNetConnect(ip, evt.Fields["remote_port"], !isPrivateAddr(ip))
		}
	case event.DataTypeDNS:
		if evt.EventType == event.DNSQuery {
			domain := evt.Fields["domain"]
			nxDomain := evt.Fields["rcode"] == "NXDOMAIN"
			e.bdeProfiler.ObserveDNSQuery(domain, nxDomain)
		}
	}
}

// bdeSnapshotLoop periodically publishes behavior profile snapshots to Server.
func (e *Engine) bdeSnapshotLoop(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(bde.SnapshotInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := e.bdeProfiler.TakeSnapshot()
			fields := bde.SnapshotToFields(snap)
			record := &bridge.Record{
				DataType:  bde.DataTypeBDE,
				Timestamp: time.Now().UnixNano(),
				Data:      &bridge.Payload{Fields: fields},
			}
			if err := e.transport.SendPluginData("edr", record); err != nil {
				e.logger.Debug("failed to send BDE snapshot", zap.Error(err))
			}
		}
	}
}

// isPrivateAddr checks if an IP address is private/reserved.
func isPrivateAddr(addr string) bool {
	if addr == "" || addr == "127.0.0.1" || addr == "::1" {
		return true
	}
	// Fast check for common private prefixes.
	if len(addr) >= 3 {
		switch {
		case addr[:3] == "10.":
			return true
		case len(addr) >= 8 && addr[:8] == "192.168.":
			return true
		case len(addr) >= 4 && addr[:4] == "172.":
			// 172.16.0.0 - 172.31.255.255
			if len(addr) >= 7 {
				second := addr[4:6]
				if len(second) >= 2 {
					d := (second[0]-'0')*10 + (second[1] - '0')
					if d >= 16 && d <= 31 {
						return true
					}
				}
			}
		}
	}
	return false
}

// inheritStory propagates story_id from parent to child on process_exec events.
func (e *Engine) inheritStory(evt *event.Event) {
	if evt.EventType != "process_exec" {
		return
	}
	ppidStr := evt.Fields["ppid"]
	pidStr := evt.Fields["pid"]
	if ppidStr == "" || pidStr == "" {
		return
	}
	ppid, err := strconv.ParseInt(ppidStr, 10, 32)
	if err != nil {
		return
	}
	pid, err := strconv.ParseInt(pidStr, 10, 32)
	if err != nil {
		return
	}
	if sid := e.storyTracker.Inherit(int32(ppid), int32(pid)); sid != "" {
		evt.SetField("story_id", sid)
	}
}

// annotateStory adds story_id to an event if the PID is tracked but story_id not yet set.
func (e *Engine) annotateStory(evt *event.Event) {
	if evt.Fields["story_id"] != "" {
		return // Already annotated (by evaluateRules or inheritStory).
	}
	pidStr := evt.Fields["pid"]
	if pidStr == "" {
		return
	}
	if sid := e.storyTracker.LookupStr(pidStr); sid != "" {
		evt.SetField("story_id", sid)
	}
}

// storyCleanupLoop periodically cleans up stale storyline entries.
func (e *Engine) storyCleanupLoop(ctx context.Context) {
	defer e.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.storyTracker.Cleanup()
		}
	}
}

// installBuiltinRules copies embedded YAML rules to the rule directory
// if no rule files exist yet (first run). Existing files are not overwritten.
func installBuiltinRules(logger *zap.Logger, ruleDir string) {
	entries, err := agentrules.BuiltinRules.ReadDir(".")
	if err != nil {
		logger.Warn("failed to read embedded rules", zap.Error(err))
		return
	}

	var installed int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		dest := filepath.Join(ruleDir, entry.Name())

		// Don't overwrite existing rules (may have been customized or pushed by Server).
		if _, err := os.Stat(dest); err == nil {
			continue
		}

		data, err := agentrules.BuiltinRules.ReadFile(entry.Name())
		if err != nil {
			logger.Warn("failed to read embedded rule", zap.String("file", entry.Name()), zap.Error(err))
			continue
		}

		if err := os.WriteFile(dest, data, 0644); err != nil {
			logger.Warn("failed to install builtin rule", zap.String("file", entry.Name()), zap.Error(err))
			continue
		}
		installed++
	}

	if installed > 0 {
		logger.Info("installed built-in rules", zap.Int("count", installed), zap.String("dir", ruleDir))
	}
}
