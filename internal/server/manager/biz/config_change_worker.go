package biz

// ConfigChangeWorker 周期扫 approved 状态的变更请求 → 应用 → applied (P1-1)。
//
// 应用规则:
//
//	feature_flags  : 更新 FeatureFlag.Value + UpdateBy=last_approver
//	system_config  : 后续扩展
//	kube_clusters  : 后续扩展
//
// 失败重试: 标 status=failed + 留 reject_reason="apply error: ..." (运维介入)。
// 成功: status=applied + applied_at=now。

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ConfigChangeWorker 后台 worker.
type ConfigChangeWorker struct {
	db       *gorm.DB
	logger   *zap.Logger
	interval time.Duration
}

// NewConfigChangeWorker 构造。interval 默认 30s。
func NewConfigChangeWorker(db *gorm.DB, logger *zap.Logger, interval time.Duration) *ConfigChangeWorker {
	if logger == nil {
		logger = zap.NewNop()
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &ConfigChangeWorker{db: db, logger: logger, interval: interval}
}

// Start 阻塞循环, 接 ctx.Done() 退出。
func (w *ConfigChangeWorker) Start(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	w.logger.Info("config change worker started", zap.Duration("interval", w.interval))
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.runOnce(ctx)
		}
	}
}

func (w *ConfigChangeWorker) runOnce(ctx context.Context) {
	var pending []model.ConfigChangeRequest
	if err := w.db.WithContext(ctx).
		Where("status = ?", "approved").
		Order("id ASC").
		Limit(50).
		Find(&pending).Error; err != nil {
		w.logger.Warn("query approved requests failed", zap.Error(err))
		return
	}
	if len(pending) == 0 {
		return
	}
	for i := range pending {
		w.apply(ctx, &pending[i])
	}
}

func (w *ConfigChangeWorker) apply(ctx context.Context, r *model.ConfigChangeRequest) {
	err := w.dispatch(ctx, r)
	if err != nil {
		r.Status = "failed"
		r.RejectReason = "apply error: " + err.Error()
		w.logger.Error("apply change failed",
			zap.Uint("id", r.ID),
			zap.String("target", r.TargetTable+"."+r.TargetKey),
			zap.Error(err))
	} else {
		r.Status = "applied"
		r.AppliedAt = model.LocalTime(time.Now())
		w.logger.Info("config change applied",
			zap.Uint("id", r.ID),
			zap.String("target", r.TargetTable+"."+r.TargetKey),
			zap.String("new_value", maybeRedact(r.TargetKey, r.ProposedValue)))
	}
	if err := w.db.WithContext(ctx).Save(r).Error; err != nil {
		w.logger.Error("save applied state failed", zap.Error(err))
	}
}

func (w *ConfigChangeWorker) dispatch(ctx context.Context, r *model.ConfigChangeRequest) error {
	switch r.TargetTable {
	case "feature_flags":
		return w.applyFeatureFlag(ctx, r)
	case "system_config":
		return w.applySystemConfig(ctx, r)
	case "kube_clusters":
		return w.applyKubeCluster(ctx, r)
	}
	return fmt.Errorf("unknown target_table %s", r.TargetTable)
}

// applySystemConfig 把 system_config 表里 key 改成 proposed_value (P4-15).
//
// 5 个微服务 (Manager/AgentCenter/Consumer/Engine/VulnSync) 启动后会通过
// SystemConfigWatcher 订阅 system_config 表的变更, 自动 hot-reload viper.
func (w *ConfigChangeWorker) applySystemConfig(ctx context.Context, r *model.ConfigChangeRequest) error {
	updatedBy := r.Approvers
	if i := strings.LastIndex(updatedBy, ","); i >= 0 {
		updatedBy = updatedBy[i+1:]
	}
	_ = updatedBy
	res := w.db.WithContext(ctx).
		Model(&model.SystemConfig{}).
		Where("tenant_id = ? AND `key` = ?", r.TenantID, r.TargetKey).
		Updates(map[string]any{
			"value": r.ProposedValue,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		sc := model.SystemConfig{
			TenantID:    r.TenantID,
			Key:         r.TargetKey,
			Value:       r.ProposedValue,
			Category:    "general",
			Description: "via ConfigChangeRequest #" + fmt.Sprint(r.ID),
		}
		return w.db.WithContext(ctx).Create(&sc).Error
	}
	return nil
}

// applyKubeCluster 改 kube_clusters 表 (CR 流程治理 KubeConfig 之类敏感配置).
func (w *ConfigChangeWorker) applyKubeCluster(ctx context.Context, r *model.ConfigChangeRequest) error {
	return w.db.WithContext(ctx).
		Table("kube_clusters").
		Where("tenant_id = ? AND id = ?", r.TenantID, r.TargetKey).
		Updates(map[string]any{
			"kubeconfig": r.ProposedValue,
		}).Error
}

func (w *ConfigChangeWorker) applyFeatureFlag(ctx context.Context, r *model.ConfigChangeRequest) error {
	// 末位 approver 视为 UpdatedBy
	updatedBy := r.Approvers
	if i := strings.LastIndex(updatedBy, ","); i >= 0 {
		updatedBy = updatedBy[i+1:]
	}
	res := w.db.WithContext(ctx).
		Model(&model.FeatureFlag{}).
		Where("tenant_id = ? AND flag_key = ?", r.TenantID, r.TargetKey).
		Updates(map[string]any{
			"value":      r.ProposedValue,
			"updated_by": updatedBy,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		// flag 不存在 → 新建
		ff := model.FeatureFlag{
			TenantID:   r.TenantID,
			Key:        r.TargetKey,
			Value:      r.ProposedValue,
			DefaultVal: r.OldValue,
			UpdatedBy:  updatedBy,
		}
		return w.db.WithContext(ctx).Create(&ff).Error
	}
	return nil
}

// maybeRedact 高敏 key 脱敏 (避免日志泄密)。
func maybeRedact(key, value string) string {
	for _, prefix := range []string{"kms.", "secret.", "password.", "token."} {
		if strings.HasPrefix(key, prefix) {
			if len(value) > 4 {
				return value[:2] + "***" + value[len(value)-2:]
			}
			return "***"
		}
	}
	return value
}
