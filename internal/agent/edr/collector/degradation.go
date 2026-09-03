//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/resource"
)

// Degradation levels control event filtering in BPF programs via config_map.
//
// Level 0 — Normal:     all events collected
// Level 1 — CPU > 60%:  drop file_open (high-volume, low-risk)
// Level 2 — CPU > 80%:  only process_exec + tcp_connect
// Level 3 — CPU > 95%:  only process_exec
// Self-kill — CPU > 98% for 5 min: stop all collection + alert
// degradeLevel3 is the maximum degradation level (process_exec only).
// Levels: 0=normal, 1=drop file_open, 2=process_exec+tcp_connect, 3=process_exec only.
const degradeLevel3 = 3

// degradeThreshold defines the upgrade/recovery thresholds for each level.
// Hysteresis: recovery threshold is 10% below upgrade threshold.
type degradeThreshold struct {
	upgradeCPU float64 // CPU % to upgrade to this level
	recoverCPU float64 // CPU % to recover from this level
}

var thresholds = []degradeThreshold{
	{}, // level 0: no upgrade threshold
	{upgradeCPU: 60, recoverCPU: 50},
	{upgradeCPU: 80, recoverCPU: 70},
	{upgradeCPU: 95, recoverCPU: 85},
}

const (
	selfKillCPU      = 98.0
	selfKillDuration = 5 * time.Minute
	monitorInterval  = 5 * time.Second
)

// DegradationManager monitors system CPU and dynamically adjusts event collection intensity.
// It updates BPF config_map in each loaded BPF object to control kernel-side filtering.
type DegradationManager struct {
	logger       *zap.Logger
	resourceMon  *resource.Monitor
	currentLevel atomic.Int32
	configMaps   []*ebpf.Map // config_map refs from process/file/network BPF objects
	onSelfKill   func()      // callback to stop all collection

	// Self-kill tracking
	selfKillStart  time.Time
	selfKillActive bool
}

// NewDegradationManager creates a degradation manager.
// configMaps: references to each BPF object's config_map (nil entries are skipped).
// onSelfKill: called when CPU > 98% for 5 continuous minutes.
func NewDegradationManager(logger *zap.Logger, configMaps []*ebpf.Map, onSelfKill func()) *DegradationManager {
	// Filter out nil maps
	var valid []*ebpf.Map
	for _, m := range configMaps {
		if m != nil {
			valid = append(valid, m)
		}
	}

	return &DegradationManager{
		logger:      logger,
		resourceMon: resource.NewMonitor(logger),
		configMaps:  valid,
		onSelfKill:  onSelfKill,
	}
}

// Level returns the current degradation level.
func (d *DegradationManager) Level() int32 {
	return d.currentLevel.Load()
}

// Monitor starts the CPU monitoring loop. Blocks until context is cancelled.
func (d *DegradationManager) Monitor(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	d.logger.Info("degradation monitor started")

	for {
		select {
		case <-ctx.Done():
			d.logger.Info("degradation monitor stopped",
				zap.Int32("final_level", d.currentLevel.Load()),
			)
			return
		case <-ticker.C:
			d.evaluate()
		}
	}
}

// evaluate collects CPU and adjusts the degradation level.
func (d *DegradationManager) evaluate() {
	metrics, err := d.resourceMon.Collect()
	if err != nil {
		d.logger.Warn("degradation: failed to collect CPU", zap.Error(err))
		return
	}

	cpu := metrics.CPUUsage
	current := int(d.currentLevel.Load())

	// Check self-kill condition
	if cpu >= selfKillCPU {
		if !d.selfKillActive {
			d.selfKillActive = true
			d.selfKillStart = time.Now()
			d.logger.Warn("degradation: CPU critical, self-kill timer started",
				zap.Float64("cpu", cpu),
			)
		} else if time.Since(d.selfKillStart) >= selfKillDuration {
			d.logger.Error("degradation: CPU > 98% for 5 minutes, triggering self-kill")
			if d.onSelfKill != nil {
				d.onSelfKill()
			}
			return
		}
	} else {
		if d.selfKillActive {
			d.selfKillActive = false
			d.logger.Info("degradation: CPU dropped below self-kill threshold",
				zap.Float64("cpu", cpu),
			)
		}
	}

	// Calculate target level with hysteresis
	newLevel := d.calculateLevel(cpu, current)
	if newLevel != current {
		d.setLevel(int32(newLevel))
		d.logger.Warn("degradation level changed",
			zap.Int("old_level", current),
			zap.Int("new_level", newLevel),
			zap.Float64("cpu", cpu),
		)
	}
}

// calculateLevel determines the target level using hysteresis.
func (d *DegradationManager) calculateLevel(cpu float64, current int) int {
	target := current

	// Check for upgrade (higher level)
	for lvl := current + 1; lvl <= degradeLevel3; lvl++ {
		if cpu >= thresholds[lvl].upgradeCPU {
			target = lvl
		} else {
			break
		}
	}

	// Check for recovery (lower level) — only if not upgrading
	if target == current && current > 0 {
		if cpu < thresholds[current].recoverCPU {
			target = current - 1
		}
	}

	return target
}

// setLevel updates the atomic level and writes to all BPF config_maps.
func (d *DegradationManager) setLevel(level int32) {
	d.currentLevel.Store(level)

	key := uint32(0)
	value := uint32(level)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)

	for _, m := range d.configMaps {
		if err := m.Update(key, buf, ebpf.UpdateAny); err != nil {
			d.logger.Warn("failed to update BPF config_map",
				zap.Int32("level", level),
				zap.Error(err),
			)
		}
	}
}
