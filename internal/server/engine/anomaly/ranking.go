package anomaly

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 排序档（ranking）：让异常分参与**已有告警**的排序。
//
// 这是 1.0 允许 ML 产生价值的唯一方式。它不新建告警、不提升严重度，只让分析师
// 在一堆同级告警里先看到异常主机上的那些。
//
// 为什么这个边界重要：无监督异常检测给出的是"少见"，不是"恶意"。少见的东西每天都有
// 一堆——季度结算、批量导数、临时扩容。让它定罪会淹没值班；让它排序则只在分析师
// 本来就要看的东西之间调整先后，代价上限是"顺序不理想"，而不是"被叫醒去看无害的事"。

// rankingFlushInterval 异常分落库间隔。
//
// 排序用的分数不需要实时：分析师看告警列表是分钟级的行为，
// 而每次评分都写库会把观测本身变成负载源。
const rankingFlushInterval = time.Minute

// anomalyScoreFlushFailed 异常分落库失败次数。
//
// 落库失败会让排序悄悄退回"没有 ML 参与"的状态——功能看起来还在，实际不起作用。
var anomalyScoreFlushFailed = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "mxcwpp_anomaly_score_flush_failed_total",
	Help: "Failures writing per-host anomaly scores used for alert ranking",
})

// scoreRecorder 累积每台主机最近的异常分并周期落库。
type scoreRecorder struct {
	db  *gorm.DB
	log *zap.Logger

	mu     sync.Mutex
	scores map[string]hostScore
}

type hostScore struct {
	score float64
	at    time.Time
}

func newScoreRecorder(db *gorm.DB, log *zap.Logger) *scoreRecorder {
	return &scoreRecorder{db: db, log: log, scores: make(map[string]hostScore)}
}

// record 记录一台主机的最新异常分。
//
// 同一周期内多次评分只保留最新的一次：排序关心的是"现在是否异常"，
// 不是这一分钟里出现过的最高分——用峰值会让一次瞬时抖动把主机顶在列表前面很久。
func (r *scoreRecorder) record(hostID string, score float64, at time.Time) {
	if hostID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.scores[hostID]; ok && prev.at.After(at) {
		return
	}
	r.scores[hostID] = hostScore{score: score, at: at}
}

// flush 落库累积的异常分。
func (r *scoreRecorder) flush() {
	r.mu.Lock()
	batch := r.scores
	r.scores = make(map[string]hostScore)
	r.mu.Unlock()

	if len(batch) == 0 || r.db == nil {
		return
	}
	for hostID, hs := range batch {
		row := model.HostAnomalyScore{
			HostID:     hostID,
			Score:      hs.score,
			ObservedAt: model.ToLocalTime(hs.at),
		}
		err := r.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "host_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"score", "observed_at"}),
		}).Create(&row).Error
		if err != nil {
			anomalyScoreFlushFailed.Inc()
			// 只影响排序，不影响检测本身，因此告警而不中断。
			r.log.Warn("异常分落库失败（该主机本轮不参与告警排序）",
				zap.String("host_id", hostID), zap.Error(err))
		}
	}
}

// StartScoreFlush 周期落库异常分。
func (r *scoreRecorder) StartScoreFlush(stop <-chan struct{}) {
	ticker := time.NewTicker(rankingFlushInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.flush()
			case <-stop:
				// 退出前落一次，避免最后一个周期的分数丢失。
				r.flush()
				return
			}
		}
	}()
}
