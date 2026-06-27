package baseline

import (
	"encoding/json"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// loadFromDB restores persisted baselines from MySQL on engine startup.
func (e *Engine) loadFromDB() {
	var states []model.HostBaselineState
	if err := e.db.Find(&states).Error; err != nil {
		e.logger.Warn("加载基线状态失败", zap.Error(err))
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, s := range states {
		bl := &HostBaseline{
			firstSeen: time.Time(s.FirstSeen),
			samples:   s.Samples,
			phase:     s.Phase,
		}
		if err := json.Unmarshal([]byte(s.MeanJSON), &bl.mean); err != nil {
			e.logger.Warn("解析基线 mean 失败", zap.String("host_id", s.HostID), zap.Error(err))
			continue
		}
		if err := json.Unmarshal([]byte(s.M2JSON), &bl.m2); err != nil {
			e.logger.Warn("解析基线 m2 失败", zap.String("host_id", s.HostID), zap.Error(err))
			continue
		}
		// 时段分桶基线（P1-A）。旧行/空值容错：解析失败则桶留空，评估回退扁平，下次 checkpoint 重建。
		if s.BSamplesJSON != "" {
			_ = json.Unmarshal([]byte(s.BMeanJSON), &bl.bMean)
			_ = json.Unmarshal([]byte(s.BM2JSON), &bl.bM2)
			_ = json.Unmarshal([]byte(s.BSamplesJSON), &bl.bSamples)
		}

		// Re-check phase after restore (time may have passed while offline).
		if bl.phase == PhaseLearning && bl.samples >= minSamples && time.Since(bl.firstSeen) >= learningPeriod {
			bl.phase = PhaseActive
		}

		e.baselines[s.HostID] = bl
	}

	e.logger.Info("基线状态已恢复", zap.Int("hosts", len(states)))
}

// checkpoint persists all dirty baselines to MySQL.
func (e *Engine) checkpoint() {
	e.mu.RLock()
	// Collect dirty baselines under read lock.
	type entry struct {
		hostID string
		bl     *HostBaseline
	}
	var dirty []entry
	for hostID, bl := range e.baselines {
		bl.mu.Lock()
		if bl.dirty {
			dirty = append(dirty, entry{hostID, bl})
		}
		bl.mu.Unlock()
	}
	e.mu.RUnlock()

	if len(dirty) == 0 {
		return
	}

	saved := 0
	for _, d := range dirty {
		d.bl.mu.Lock()
		meanJSON, err := json.Marshal(d.bl.mean)
		if err != nil {
			d.bl.mu.Unlock()
			continue
		}
		m2JSON, err := json.Marshal(d.bl.m2)
		if err != nil {
			d.bl.mu.Unlock()
			continue
		}
		// 时段分桶基线（P1-A）：marshal 失败不阻断扁平持久化，置空即可。
		bMeanJSON, _ := json.Marshal(d.bl.bMean)
		bM2JSON, _ := json.Marshal(d.bl.bM2)
		bSamplesJSON, _ := json.Marshal(d.bl.bSamples)

		state := model.HostBaselineState{
			HostID:       d.hostID,
			Phase:        d.bl.phase,
			Samples:      d.bl.samples,
			FirstSeen:    model.LocalTime(d.bl.firstSeen),
			MeanJSON:     string(meanJSON),
			M2JSON:       string(m2JSON),
			BMeanJSON:    string(bMeanJSON),
			BM2JSON:      string(bM2JSON),
			BSamplesJSON: string(bSamplesJSON),
		}
		d.bl.dirty = false
		d.bl.mu.Unlock()

		// Upsert: create or update by host_id.
		result := e.db.Where("host_id = ?", d.hostID).
			Assign(state).
			FirstOrCreate(&model.HostBaselineState{})
		if result.Error != nil {
			e.logger.Warn("持久化基线失败", zap.String("host_id", d.hostID), zap.Error(result.Error))
			d.bl.mu.Lock()
			d.bl.dirty = true // Mark dirty again for retry.
			d.bl.mu.Unlock()
			continue
		}
		saved++
	}

	e.logger.Debug("基线检查点完成", zap.Int("saved", saved), zap.Int("total_dirty", len(dirty)))
}
