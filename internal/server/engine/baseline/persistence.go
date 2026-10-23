package baseline

import (
	"encoding/json"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// baselineAlgoEWMA 标识 host_baseline_states 行的方差口径为指数加权(EWMV，M2JSON 存 variance)。
// 空/其他值视为旧 Welford 行(M2JSON 存 sum-of-squared-deviations)，加载时换算。
const baselineAlgoEWMA = "ewma"

// welfordM2ToVariance 把旧 Welford 的 sum-of-squared-deviations 按 (samples-1) 换算成样本方差，
// 作为 EWMA/EWMV 的种子（一次性迁移，samples<2 时方差为 0）。
func welfordM2ToVariance(m2 [MetricCount]float64, samples int) [MetricCount]float64 {
	var out [MetricCount]float64
	if samples < 2 {
		return out
	}
	n := float64(samples - 1)
	for i := range m2 {
		out[i] = m2[i] / n
	}
	return out
}

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
		var m2 [MetricCount]float64
		if err := json.Unmarshal([]byte(s.M2JSON), &m2); err != nil {
			e.logger.Warn("解析基线 m2 失败", zap.String("host_id", s.HostID), zap.Error(err))
			continue
		}
		// 旧 Welford 行(algo != ewma): M2JSON 存 sum-of-squared-deviations，按 (samples-1)
		// 换算成 variance 作 EWMA 种子；已是 ewma 行则 M2JSON 直接是 variance。
		if s.Algo == baselineAlgoEWMA {
			bl.variance = m2
		} else {
			bl.variance = welfordM2ToVariance(m2, bl.samples)
		}
		// 时段分桶基线（P1-A）。旧行/空值容错：解析失败则桶留空，评估回退扁平，下次 checkpoint 重建。
		if s.BSamplesJSON != "" {
			_ = json.Unmarshal([]byte(s.BMeanJSON), &bl.bMean)
			_ = json.Unmarshal([]byte(s.BSamplesJSON), &bl.bSamples)
			var bm2 [NumTimeBuckets][MetricCount]float64
			if json.Unmarshal([]byte(s.BM2JSON), &bm2) == nil {
				for k := range bl.bVar {
					if s.Algo == baselineAlgoEWMA {
						bl.bVar[k] = bm2[k]
					} else {
						bl.bVar[k] = welfordM2ToVariance(bm2[k], bl.bSamples[k])
					}
				}
			}
		}

		// Re-check phase after restore (time may have passed while offline).
		// 标 dirty 让本次毕业落库，否则内存已 active 但 DB 永远 learning（UI 读 DB）。
		if bl.phase == PhaseLearning && bl.samples >= minSamples && time.Since(bl.firstSeen) >= learningPeriod {
			bl.phase = PhaseActive
			bl.dirty = true
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
		// M2JSON 存 EWMV variance（algo=ewma），非旧 Welford 的 sum-of-squares。
		varianceJSON, err := json.Marshal(d.bl.variance)
		if err != nil {
			d.bl.mu.Unlock()
			continue
		}
		// 时段分桶基线（P1-A）：marshal 失败不阻断扁平持久化，置空即可。
		bMeanJSON, _ := json.Marshal(d.bl.bMean)
		bVarJSON, _ := json.Marshal(d.bl.bVar)
		bSamplesJSON, _ := json.Marshal(d.bl.bSamples)

		state := model.HostBaselineState{
			HostID:       d.hostID,
			Phase:        d.bl.phase,
			Samples:      d.bl.samples,
			FirstSeen:    model.LocalTime(d.bl.firstSeen),
			Algo:         baselineAlgoEWMA,
			MeanJSON:     string(meanJSON),
			M2JSON:       string(varianceJSON),
			BMeanJSON:    string(bMeanJSON),
			BM2JSON:      string(bVarJSON),
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
