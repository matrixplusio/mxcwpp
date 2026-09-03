//go:build linux

package collector

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
	"github.com/matrixplusio/mxcwpp/internal/agent/resource"
)

// userspaceCollector implements Collector using userspace APIs for old kernels (< 5.4).
//   - Process events: cn_proc (netlink PROC_EVENT)
//   - File events: fanotify (FAN_CLOSE_WRITE)
//   - Network events: /proc/net/tcp + /proc/net/udp polling (5s interval)
type userspaceCollector struct {
	logger  *zap.Logger
	eventCh chan *event.Event // external channel (filtered)
	rawCh   chan *event.Event // internal channel (unfiltered, sub-modules write here)

	cnproc   *cnProcListener
	fanotify *fanotifyListener
	procnet  *procNetPoller
	scanner  *procScanner

	cnprocOK   bool
	fanotifyOK bool
	procnetOK  bool

	degradeLevel atomic.Int32

	wg sync.WaitGroup
}

func newUserspaceCollector(logger *zap.Logger) (*userspaceCollector, error) {
	return &userspaceCollector{
		logger: logger,
	}, nil
}

func (c *userspaceCollector) Mode() Mode {
	return ModeUserspace
}

func (c *userspaceCollector) HookType() HookType {
	return HookKprobe // not applicable for userspace, but satisfies interface
}

// DegradationLevel returns the current dynamic degradation level (0-3).
func (c *userspaceCollector) DegradationLevel() int32 {
	return c.degradeLevel.Load()
}

func (c *userspaceCollector) Capabilities() []Capability {
	var caps []Capability
	if c.cnprocOK {
		caps = append(caps, CapProcessBasic)
	}
	if c.fanotifyOK {
		caps = append(caps, CapFileBasic)
	}
	if c.procnetOK {
		caps = append(caps, CapNetworkBasic)
	}
	return caps
}

func (c *userspaceCollector) Start(ctx context.Context) (<-chan *event.Event, error) {
	c.eventCh = make(chan *event.Event, 4096)
	c.rawCh = make(chan *event.Event, 4096)

	// --- cn_proc (process events) ---
	cnp, err := newCNProcListener(c.logger, c.rawCh)
	if err != nil {
		c.logger.Warn("cn_proc init failed, process events unavailable", zap.Error(err))
	} else {
		c.cnproc = cnp
		c.cnprocOK = true
		c.wg.Add(1)
		go c.cnproc.readLoop(ctx, &c.wg)
		c.logger.Info("cn_proc listener started")
	}

	// --- fanotify (file events) ---
	fan, err := newFanotifyListener(c.logger, c.rawCh)
	if err != nil {
		c.logger.Warn("fanotify init failed, file events unavailable", zap.Error(err))
	} else {
		c.fanotify = fan
		c.fanotifyOK = true
		c.wg.Add(1)
		go c.fanotify.readLoop(ctx, &c.wg)
		c.logger.Info("fanotify listener started")
	}

	// --- /proc/net poller (network events) ---
	pn := newProcNetPoller(c.logger, c.rawCh, 5*time.Second)
	c.procnet = pn
	c.procnetOK = true
	c.wg.Add(1)
	go c.procnet.pollLoop(ctx, &c.wg)
	c.logger.Info("procnet poller started")

	// --- /proc initial snapshot ---
	c.scanner = newProcScanner(c.logger, c.rawCh)
	if err := c.scanner.initialSnapshot(); err != nil {
		c.logger.Warn("initial proc snapshot failed", zap.Error(err))
	}

	// --- /proc reconciliation loop (5 min) ---
	c.wg.Add(1)
	go c.scanner.reconcileLoop(ctx, &c.wg, 5*time.Minute)

	// --- Degradation filter goroutine ---
	c.wg.Add(1)
	go c.filterEvents(ctx)

	// --- CPU degradation monitor ---
	c.wg.Add(1)
	go c.monitorCPU(ctx)

	c.logger.Info("userspace collector started",
		zap.Bool("cn_proc", c.cnprocOK),
		zap.Bool("fanotify", c.fanotifyOK),
		zap.Bool("procnet", c.procnetOK),
	)

	// Close rawCh when all producer goroutines finish, then eventCh after filter exits.
	go func() {
		c.wg.Wait()
		close(c.eventCh)
		c.logger.Info("userspace collector stopped")
	}()

	return c.eventCh, nil
}

// filterEvents reads from rawCh, applies degradation filtering, and forwards to eventCh.
func (c *userspaceCollector) filterEvents(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-c.rawCh:
			if !ok {
				return
			}
			if c.shouldEmit(evt) {
				select {
				case c.eventCh <- evt:
				case <-ctx.Done():
					return
				default:
				}
			}
		}
	}
}

// shouldEmit checks whether an event should pass through the degradation filter.
// Same rules as BPF-side filtering:
//
//	Level 1: drop file_open (FileWrite from fanotify maps to file_write, always pass)
//	Level 2: only process_exec + tcp_connect
//	Level 3: only process_exec
func (c *userspaceCollector) shouldEmit(evt *event.Event) bool {
	level := c.degradeLevel.Load()
	if level == 0 {
		return true
	}

	switch evt.DataType {
	case event.DataTypeProcess:
		// Level 3: only process_exec
		if level >= 3 && evt.EventType == event.ProcessExit {
			return false
		}
		return true

	case event.DataTypeFile:
		// Level 1: drop file_open; Level 2+: drop all file events
		if level >= 2 {
			return false
		}
		if level >= 1 && evt.EventType == event.FileOpen {
			return false
		}
		return true

	case event.DataTypeNetwork:
		// Level 3+: drop all network events
		if level >= 3 {
			return false
		}
		// Level 2: only tcp_connect
		if level >= 2 && evt.EventType != event.TCPConnect {
			return false
		}
		return true
	}

	return true
}

// monitorCPU periodically checks system CPU and adjusts degradation level.
// Reuses the same threshold/hysteresis logic as DegradationManager.
func (c *userspaceCollector) monitorCPU(ctx context.Context) {
	defer c.wg.Done()

	mon := resource.NewMonitor(c.logger)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics, err := mon.Collect()
			if err != nil {
				continue
			}
			cpu := metrics.CPUUsage
			current := int(c.degradeLevel.Load())
			newLevel := calculateDegradeLevel(cpu, current)
			if newLevel != current {
				c.degradeLevel.Store(int32(newLevel))
				c.logger.Warn("userspace degradation level changed",
					zap.Int("old_level", current),
					zap.Int("new_level", newLevel),
					zap.Float64("cpu", cpu),
				)
			}
		}
	}
}

// calculateDegradeLevel determines target level using hysteresis.
// Shared logic between eBPF DegradationManager and userspace collector.
func calculateDegradeLevel(cpu float64, current int) int {
	type threshold struct {
		upgrade float64
		recover float64
	}
	levels := []threshold{
		{}, // level 0
		{upgrade: 60, recover: 50},
		{upgrade: 80, recover: 70},
		{upgrade: 95, recover: 85},
	}

	target := current

	// Check upgrade
	for lvl := current + 1; lvl < len(levels); lvl++ {
		if cpu >= levels[lvl].upgrade {
			target = lvl
		} else {
			break
		}
	}

	// Check recovery
	if target == current && current > 0 {
		if cpu < levels[current].recover {
			target = current - 1
		}
	}

	return target
}

func (c *userspaceCollector) Stop() error {
	if c.cnproc != nil {
		c.cnproc.close()
	}
	if c.fanotify != nil {
		c.fanotify.close()
	}
	c.logger.Info("userspace collector resources released")
	return nil
}

// String implements fmt.Stringer for logging.
func (c *userspaceCollector) String() string {
	return fmt.Sprintf("userspace-collector(mode=%s)", c.Mode())
}
