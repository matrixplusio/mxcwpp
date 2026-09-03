// Package audit 提供操作审计的中央记录器。
//
// 统一所有审计落库入口（HTTP 中间件 / 认证埋点 / 系统调度 / agent 事件），
// 按 feature_flag.data_source.audit_log 决定写 ClickHouse 还是 MySQL，CH 失败回落 MySQL。
// 通过 Init 注入依赖后以单例方式被各处 Record 调用。
package audit

import (
	"context"
	"sync"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Event 描述一条待记录的审计事件。
//
// Action 为语义动词（如 user.login / role.delete / vuln.scan），
// 由调用方显式给出或经 SemanticAction 从路由推导。
type Event struct {
	ActorType    string // user/system/agent，空则按 user
	Username     string // 操作者；system/agent 可填任务名或 agent_id
	Action       string // 语义动词
	Outcome      string // success/failure，空则按 success
	ResourceType string
	ResourceID   string
	TargetName   string // 资源可读名（角色名/用户名/主机名）
	Path         string
	IP           string
	Detail       string // 请求体摘要
	ChangeDetail string // 变更详情 before→after
	StatusCode   int
}

// Recorder 审计记录器，持有写入依赖与目标通道。
type Recorder struct {
	db     *gorm.DB
	chConn chdriver.Conn
	target string // "ch" or "mysql"
	logger *zap.Logger
}

var (
	global *Recorder
	mu     sync.RWMutex
)

// Init 初始化全局记录器（路由初始化时调用一次）。
// 读 feature_flag.data_source.audit_log 决定通道，chConn 为 nil 时强制 MySQL。
func Init(db *gorm.DB, chConn chdriver.Conn, logger *zap.Logger) *Recorder {
	if logger == nil {
		logger = zap.NewNop()
	}
	r := &Recorder{
		db:     db,
		chConn: chConn,
		target: readTarget(db, logger),
		logger: logger,
	}
	logger.Info("审计记录器初始化", zap.String("target", r.target), zap.Bool("ch_available", chConn != nil))
	mu.Lock()
	global = r
	mu.Unlock()
	return r
}

// Record 经全局记录器落库一条审计事件；记录器未初始化时安全空操作。
func Record(ctx context.Context, e Event) {
	mu.RLock()
	r := global
	mu.RUnlock()
	if r == nil {
		return
	}
	r.Record(ctx, e)
}

// Record 落库一条审计事件。CH 写失败回落 MySQL。
func (r *Recorder) Record(ctx context.Context, e Event) {
	if e.ActorType == "" {
		e.ActorType = model.ActorTypeUser
	}
	if e.Outcome == "" {
		e.Outcome = model.OutcomeSuccess
	}
	if e.Username == "" {
		e.Username = "unknown"
	}

	log := &model.AuditLog{
		ActorType:    e.ActorType,
		Username:     e.Username,
		Action:       e.Action,
		Outcome:      e.Outcome,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		TargetName:   e.TargetName,
		Path:         e.Path,
		IP:           e.IP,
		Detail:       e.Detail,
		ChangeDetail: e.ChangeDetail,
		StatusCode:   e.StatusCode,
	}

	if r.target == "ch" && r.chConn != nil {
		if err := r.writeCH(ctx, log); err != nil {
			r.logger.Warn("审计日志 CH 写入失败，回落 MySQL", zap.Error(err))
			if err := r.db.Create(log).Error; err != nil {
				r.logger.Warn("审计日志 MySQL 写入失败", zap.Error(err))
			}
		}
		return
	}
	if err := r.db.Create(log).Error; err != nil {
		r.logger.Warn("记录审计日志失败", zap.Error(err))
	}
}

// writeCH 把单条审计日志写到 CH mxcwpp.audit_log（语义列 + 兼容旧复合列）。
func (r *Recorder) writeCH(ctx context.Context, log *model.AuditLog) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	batch, err := r.chConn.PrepareBatch(ctx,
		"INSERT INTO audit_log (timestamp, user_id, actor_type, action, outcome, resource, resource_type, resource_id, target_name, path, status_code, detail, change_detail, ip)")
	if err != nil {
		return err
	}
	// resource 旧复合列：resource_type/resource_id path，兼容存量查询。
	resource := log.ResourceType
	if log.ResourceID != "" {
		resource = resource + "/" + log.ResourceID
	}
	if log.Path != "" {
		resource = resource + " " + log.Path
	}
	ts := time.Time(log.CreatedAt)
	if ts.IsZero() {
		ts = time.Now()
	}
	if err := batch.Append(
		ts, log.Username, log.ActorType, log.Action, log.Outcome,
		resource, log.ResourceType, log.ResourceID, log.TargetName, log.Path,
		int32(log.StatusCode), log.Detail, log.ChangeDetail, log.IP,
	); err != nil {
		return err
	}
	return batch.Send()
}

// readTarget 启动时读 feature_flag.data_source.audit_log；不缓存运行时变化，需重启生效。
func readTarget(db *gorm.DB, logger *zap.Logger) string {
	var f model.FeatureFlag
	if err := db.Where("flag_key = ?", model.FlagDataSourceAuditLog).First(&f).Error; err != nil {
		logger.Warn("audit_log feature flag 读取失败，使用 mysql 默认", zap.Error(err))
		return "mysql"
	}
	if f.Value != "ch" {
		return "mysql"
	}
	return "ch"
}

// statusToOutcome 按 HTTP 状态码推导结果。
func statusToOutcome(status int) string {
	if status >= 400 {
		return model.OutcomeFailure
	}
	return model.OutcomeSuccess
}
