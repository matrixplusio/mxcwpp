package risk

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Persister 把判断追加写进 risk_decisions（见 model.RiskDecision）。
func Persister(db *gorm.DB) func(model.RiskDecision) error {
	return func(d model.RiskDecision) error { return db.Create(&d).Error }
}

// decisionRetention 影子判断的保留期：影子期两周，留足对照与复盘的余量。
const decisionRetention = 30 * 24 * time.Hour

// StartRetention 每小时删掉保留期以外的判断，分批删，不长时间锁表。
func StartRetention(ctx context.Context, db *gorm.DB, logger *zap.Logger) {
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cutoff := model.ToLocalTime(time.Now().Add(-decisionRetention))
				for i := 0; i < 100; i++ {
					res := db.Where("created_at < ?", cutoff).Limit(5000).Delete(&model.RiskDecision{})
					if res.Error != nil {
						logger.Warn("清理过期风险判断失败", zap.Error(res.Error))
						break
					}
					if res.RowsAffected < 5000 {
						break
					}
				}
			}
		}
	}()
}

// prevalenceReload 系数表的刷新周期。consumer 每小时重算一次，这里跟上即可。
const prevalenceReload = 15 * time.Minute

// prevalenceMaxAge 系数表超过这么久没更新就不用：consumer 停了之后，旧的降分系数不能无限期生效。
const prevalenceMaxAge = 3 * time.Hour

var (
	prevalenceRows = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "mxcwpp", Subsystem: "engine", Name: "risk_prevalence_rows",
		Help: "Fresh rule+exe prevalence entries in use; 0 means no scores are being lowered.",
	})
	prevalenceLoadFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mxcwpp", Subsystem: "engine", Name: "risk_prevalence_load_failures_total",
		Help: "Failed loads of the prevalence table; the previous snapshot is used until it goes stale.",
	})
)

// prevalenceSnap 系数快照与加载时间。
type prevalenceSnap struct {
	factors  map[string]float64
	loadedAt time.Time
}

// Prevalence 「规则 + 程序」的普遍性系数，从 signal_prevalence 表加载。
type Prevalence struct {
	db   *gorm.DB
	log  *zap.Logger
	snap atomic.Pointer[prevalenceSnap]
}

// NewPrevalence 构造并立即加载一次。
func NewPrevalence(db *gorm.DB, logger *zap.Logger) *Prevalence {
	p := &Prevalence{db: db, log: logger}
	p.reload()
	return p
}

// Factor 普遍性系数：超过一半登记主机都出现过的按 0.3，10%～50% 按 0.7，其余 1。
// 表里查不到（罕见、或统计还没跑过）一律按 1——不确定时不降分。
func (p *Prevalence) Factor(ruleKey, exe string) float64 {
	snap := p.snap.Load()
	// 一直加载失败时旧快照不能无限期生效：超过过期时间就不再降分。
	if snap == nil || time.Since(snap.loadedAt) > prevalenceMaxAge {
		return 1
	}
	if f, ok := snap.factors[ruleKey+"\x00"+clip(exe, 255)]; ok {
		return f
	}
	return 1
}

// FactorFor 按覆盖比例给出系数。
func FactorFor(hosts, total int) float64 {
	if total <= 0 || hosts <= 0 {
		return 1
	}
	share := float64(hosts) / float64(total)
	switch {
	case share > 0.5:
		return 0.3
	case share >= 0.1:
		return 0.7
	}
	return 1
}

func (p *Prevalence) reload() {
	if p.db == nil {
		return
	}
	var rows []model.SignalPrevalence
	if err := p.db.Find(&rows).Error; err != nil {
		// 加载失败保留旧表；从没加载成功过时 Factor 一律返回 1，不降分。
		prevalenceLoadFailures.Inc()
		p.log.Warn("加载信号普遍性失败，沿用旧数据", zap.Error(err))
		return
	}
	m := make(map[string]float64, len(rows))
	cutoff := time.Now().Add(-prevalenceMaxAge)
	stale := 0
	for _, r := range rows {
		if time.Time(r.UpdatedAt).Before(cutoff) {
			stale++
			continue
		}
		m[r.RuleID+"\x00"+r.Exe] = FactorFor(r.Hosts, r.TotalHosts)
	}
	if stale > 0 {
		p.log.Warn("信号普遍性表已过期，过期部分不再降分（查 consumer 的普遍性统计）", zap.Int("stale", stale))
	}
	prevalenceRows.Set(float64(len(m)))
	p.snap.Store(&prevalenceSnap{factors: m, loadedAt: time.Now()})
}

// Start 周期刷新，直到 ctx 取消。
func (p *Prevalence) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(prevalenceReload)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.reload()
			}
		}
	}()
}
