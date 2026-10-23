package intrusion

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// DefaultProfileCheckpointInterval 是画像落盘周期，取值同 BDE 基线检查点。
// 画像丢一个周期的更新只是少几次登录记录，不值得为它上更密的写。
const DefaultProfileCheckpointInterval = 5 * time.Minute

// LoadFromDB 在启动时恢复画像。没有配持久化后端时是空操作。
//
// 恢复的是画像本身，不是「已毕业」这个结论: graduated 每次现算，
// 进程离线期间流逝的时间照样计入学习期。
func (d *AbnormalLoginDetector) LoadFromDB() {
	if d.db == nil {
		return
	}
	var states []model.HostLoginProfileState
	if err := d.db.Find(&states).Error; err != nil {
		d.logger.Warn("加载登录画像失败", zap.Error(err))
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	restored := 0
	for _, s := range states {
		if s.HostID == "" {
			continue
		}
		p := newProfile(time.Time(s.FirstSeen))
		p.Samples = s.Samples
		p.UpdatedAt = time.Time(s.UpdatedAt)
		// 任何一维解析失败都只丢那一维，画像其余部分照常恢复——
		// 整条丢弃等于把这台主机打回冷启动，那正是这张表要避免的事。
		unmarshalInto(s.CountriesJSON, &p.Countries, d.logger, s.HostID, "countries")
		unmarshalInto(s.HoursJSON, &p.HourBuckets, d.logger, s.HostID, "hours")
		unmarshalInto(s.UsersJSON, &p.UsersSeen, d.logger, s.HostID, "users")
		unmarshalInto(s.IPNetsJSON, &p.IPv4Net24, d.logger, s.HostID, "ip_nets")
		d.profiles[s.HostID] = p
		restored++
	}

	d.logger.Info("登录画像已恢复", zap.Int("hosts", restored))
}

// unmarshalInto 解析一维画像；空串按「没有这一维」处理，解析失败只记日志。
func unmarshalInto[T any](raw string, dst *T, logger *zap.Logger, hostID, dim string) {
	if raw == "" {
		return
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		logger.Warn("解析登录画像失败",
			zap.String("host_id", hostID), zap.String("dimension", dim), zap.Error(err))
	}
}

// Checkpoint 把有变更的画像 upsert 到 MySQL。没有持久化后端时是空操作。
func (d *AbnormalLoginDetector) Checkpoint() {
	if d.db == nil {
		return
	}

	type pending struct {
		hostID string
		state  model.HostLoginProfileState
	}

	d.mu.Lock()
	var batch []pending
	for hostID, p := range d.profiles {
		if !p.dirty {
			continue
		}
		state, err := p.toState(hostID)
		if err != nil {
			d.logger.Warn("序列化登录画像失败", zap.String("host_id", hostID), zap.Error(err))
			continue
		}
		p.dirty = false
		batch = append(batch, pending{hostID: hostID, state: state})
	}
	d.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	saved := 0
	var failed []string
	for _, b := range batch {
		// Upsert by host_id: 该列是唯一索引。
		err := d.db.Where("host_id = ?", b.hostID).
			Assign(b.state).
			FirstOrCreate(&model.HostLoginProfileState{}).Error
		if err != nil {
			d.logger.Warn("持久化登录画像失败", zap.String("host_id", b.hostID), zap.Error(err))
			failed = append(failed, b.hostID)
			continue
		}
		saved++
	}

	// 写失败的重新标脏，下个周期重试。期间画像可能又更新过，重标只会多写一次。
	if len(failed) > 0 {
		d.mu.Lock()
		for _, hostID := range failed {
			if p := d.profiles[hostID]; p != nil {
				p.dirty = true
			}
		}
		d.mu.Unlock()
	}

	d.logger.Debug("登录画像检查点完成", zap.Int("saved", saved), zap.Int("total_dirty", len(batch)))
}

// toState 序列化一份画像。调用方持锁。
func (p *loginProfile) toState(hostID string) (model.HostLoginProfileState, error) {
	countries, err := json.Marshal(p.Countries)
	if err != nil {
		return model.HostLoginProfileState{}, err
	}
	hours, err := json.Marshal(p.HourBuckets)
	if err != nil {
		return model.HostLoginProfileState{}, err
	}
	users, err := json.Marshal(p.UsersSeen)
	if err != nil {
		return model.HostLoginProfileState{}, err
	}
	ipNets, err := json.Marshal(p.IPv4Net24)
	if err != nil {
		return model.HostLoginProfileState{}, err
	}
	return model.HostLoginProfileState{
		HostID:        hostID,
		Samples:       p.Samples,
		FirstSeen:     model.LocalTime(p.FirstSeen),
		CountriesJSON: string(countries),
		HoursJSON:     string(hours),
		UsersJSON:     string(users),
		IPNetsJSON:    string(ipNets),
	}, nil
}

// StartCheckpoint 起周期落盘协程，ctx 取消时再落一次盘后退出。
// interval 非正时用 DefaultProfileCheckpointInterval。
func (d *AbnormalLoginDetector) StartCheckpoint(ctx context.Context, interval time.Duration) {
	if d.db == nil {
		return
	}
	if interval <= 0 {
		interval = DefaultProfileCheckpointInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				d.Checkpoint() // 优雅退出时不丢最后一个周期的画像
				return
			case <-ticker.C:
				d.Checkpoint()
			}
		}
	}()
}
