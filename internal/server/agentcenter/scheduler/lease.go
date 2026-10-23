package scheduler

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Lease 基于 MySQL 一行记录的调度租约。
//
// 升级、重启推送按库里的推送记录与在线主机工作，多台 AC 各跑一份会抢同一条记录、
// 重复下发。租约让它们同一时刻只在一台上跑；命令经 transfer.RouteCommand 转到
// 持有连接的实例，所以单台也能覆盖全部 agent。持有者退出后租约在 ttl 内过期，另一台接手。
type Lease struct {
	db     *gorm.DB
	name   string
	holder string
	ttl    time.Duration
	logger *zap.Logger
	held   bool
	now    func() time.Time
}

// NewLease 创建租约。ttl 应明显大于调度周期，避免持有者正常运行时被抢走。
func NewLease(db *gorm.DB, name, holder string, ttl time.Duration, logger *zap.Logger) *Lease {
	return &Lease{db: db, name: name, holder: holder, ttl: ttl, logger: logger, now: time.Now}
}

// newLeaseUnlessStandby 备用实例返回 nil：调用方据此不运行该调度器。
func newLeaseUnlessStandby(db *gorm.DB, name string, svc interface {
	InstanceID() string
	Standby() bool
}, ttl time.Duration, logger *zap.Logger) *Lease {
	if svc.Standby() {
		logger.Info("备用 AC，不参与调度租约", zap.String("lease", name))
		return nil
	}
	return NewLease(db, name, svc.InstanceID(), ttl, logger)
}

// Hold 尝试取得或续期租约，返回本实例此刻是否持有。
func (l *Lease) Hold() bool {
	now := l.now()
	exp := model.ToLocalTime(now.Add(l.ttl))
	// 首次：没有这一行就由本实例创建。已存在则忽略，走下面的条件续期。
	if err := l.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.SchedulerLease{
		Name: l.name, Holder: l.holder, ExpiresAt: exp,
	}).Error; err != nil {
		l.logger.Warn("创建调度租约失败", zap.String("lease", l.name), zap.Error(err))
		return l.set(false)
	}
	res := l.db.Model(&model.SchedulerLease{}).
		Where("name = ? AND (holder = ? OR expires_at < ?)", l.name, l.holder, model.ToLocalTime(now)).
		Updates(map[string]any{"holder": l.holder, "expires_at": exp})
	if res.Error != nil {
		l.logger.Warn("续期调度租约失败", zap.String("lease", l.name), zap.Error(res.Error))
		return l.set(false)
	}
	return l.set(res.RowsAffected == 1)
}

func (l *Lease) set(held bool) bool {
	if held != l.held {
		l.logger.Info("调度租约变更", zap.String("lease", l.name), zap.String("holder", l.holder), zap.Bool("held", held))
	}
	l.held = held
	return held
}
