package celengine

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 影子命中指标。
//
// 影子规则不告警，但必须留下痕迹：一条没人能观测的规则等于没上线，
// 而"看不到就以为没问题"正是把噪声规则一路放进告警阶段的原因。
var shadowHits = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "mxcwpp_rule_shadow_hits_total",
	Help: "Hits by detection rules in shadow stage (no alert produced)",
}, []string{"rule_id"})

// shadowFlushInterval 影子命中统计的落库间隔。
//
// 一分钟的粒度对晋级决策足够：这些数字要看的是天级趋势，不是实时曲线。
const shadowFlushInterval = time.Minute

// shadowRecorder 累计影子命中并周期落库。
//
// 不在命中时直接写库：影子阶段的规则往往正是高频噪声规则，逐次写库会把
// 观察本身变成故障源——本来要量的就是"它会响多少次"。
type shadowRecorder struct {
	db  *gorm.DB
	log *zap.Logger

	mu    sync.Mutex
	hits  map[string]int64
	hosts map[string]map[string]struct{}
}

func newShadowRecorder(db *gorm.DB, log *zap.Logger) *shadowRecorder {
	return &shadowRecorder{
		db:    db,
		log:   log,
		hits:  make(map[string]int64),
		hosts: make(map[string]map[string]struct{}),
	}
}

// record 累计一次影子命中。
func (r *shadowRecorder) record(ruleID, hostID string) {
	shadowHits.WithLabelValues(ruleID).Inc()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits[ruleID]++
	if r.hosts[ruleID] == nil {
		r.hosts[ruleID] = make(map[string]struct{})
	}
	r.hosts[ruleID][hostID] = struct{}{}
}

// flush 将累计量合并入库。
func (r *shadowRecorder) flush() {
	r.mu.Lock()
	hits, hosts := r.hits, r.hosts
	r.hits = make(map[string]int64)
	r.hosts = make(map[string]map[string]struct{})
	r.mu.Unlock()

	if len(hits) == 0 {
		return
	}
	now := model.Now()
	for ruleID, n := range hits {
		stat := model.RuleShadowStat{
			RuleID:        ruleID,
			Hits:          n,
			Hosts:         len(hosts[ruleID]),
			FirstHitAt:    &now,
			LastHitAt:     &now,
			ObservedSince: now,
		}
		// 累加而非覆盖：每轮只提交本轮增量。
		//
		// hosts 取两者较大值而不是相加：跨轮次的主机集合会重叠，相加会把
		// 同一台机器数很多次，让"只在一台机器上响"看起来像全网命中。
		err := r.db.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "rule_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"hits": gorm.Expr("hits + ?", n),
				// 用 CASE 而非 GREATEST：后者是 MySQL 方言，测试用的 sqlite 不认，
				// 写死方言会让这段逻辑只在其中一处被验证过。
				"hosts": gorm.Expr("CASE WHEN hosts < ? THEN ? ELSE hosts END",
					len(hosts[ruleID]), len(hosts[ruleID])),
				"last_hit_at": now,
			}),
		}).Create(&stat).Error
		if err != nil {
			// 落库失败只丢统计，不能影响检测：影子统计是决策辅助，
			// 不是检测链路的一环。
			r.log.Warn("影子命中统计落库失败",
				zap.String("rule_id", ruleID), zap.Error(err))
		}
	}
}

// StartShadowFlush 周期落盘影子命中统计。
func (r *shadowRecorder) StartShadowFlush(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			r.flush()
		}
	}()
}
