package anomaly

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 模型版本与回滚。
//
// 没有版本就没有回滚：一旦某轮重训学坏了，唯一的补救是等下一个 30 分钟周期，
// 赌它这次能学好——而在那之前检测一直在用坏模型打分。

// anomalyModelVersion 当前生效的模型版本号。
//
// 版本号停滞说明模型长期没有更新（可能被漂移闸持续拒绝），
// 这与「一切正常」在其它指标上看起来一样。
var anomalyModelVersion = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "mxcwpp_anomaly_model_version",
	Help: "Currently active anomaly model version",
})

// saveModelVersion 保存一次成功训练的模型，并设为生效版本。
//
// 保存失败不影响本轮检测：模型已经在内存里生效了，落库只决定重启后能否恢复
// 以及将来能否回滚。因此告警而不中断。
func (d *Detector) saveModelVersion(samples int, maxDrift float64) {
	if d.db == nil {
		return
	}
	payload, err := d.forest.MarshalForest()
	if err != nil || len(payload) == 0 {
		if err != nil {
			d.logger.Warn("序列化模型失败（本轮不产生可回滚版本）", zap.Error(err))
		}
		return
	}

	var maxVer int
	row := d.db.Model(&model.AnomalyModelVersion{}).
		Where("model_name = ?", modelStateName).
		Select("COALESCE(MAX(version), 0)")
	if err := row.Scan(&maxVer).Error; err != nil {
		d.logger.Warn("读取模型版本号失败", zap.Error(err))
		return
	}
	next := maxVer + 1

	err = d.db.Transaction(func(tx *gorm.DB) error {
		// 先摘掉旧的生效标记，再插入新版本：任一时刻只应有一个 active。
		if err := tx.Model(&model.AnomalyModelVersion{}).
			Where("model_name = ? AND active = ?", modelStateName, true).
			Update("active", false).Error; err != nil {
			return err
		}
		v := model.AnomalyModelVersion{
			ModelName:     modelStateName,
			ModelNameIdx:  modelStateName,
			Version:       next,
			Payload:       string(payload),
			Samples:       samples,
			MaxDriftSigma: maxDrift,
			Active:        true,
		}
		return tx.Create(&v).Error
	})
	if err != nil {
		d.logger.Warn("保存模型版本失败（重启后无法恢复该版本，且暂无回滚点）", zap.Error(err))
		return
	}

	anomalyModelVersion.Set(float64(next))
	d.logger.Info("模型版本已保存",
		zap.Int("version", next),
		zap.Int("samples", samples),
		zap.Int("payload_bytes", len(payload)))

	d.pruneModelVersions()
}

// pruneModelVersions 只保留最近若干个版本。
//
// 生效版本永不删除：删掉正在用的版本会让重启后无模型可加载，
// 而这种失败要到下一次重启才暴露。
func (d *Detector) pruneModelVersions() {
	var keep []int
	err := d.db.Model(&model.AnomalyModelVersion{}).
		Where("model_name = ?", modelStateName).
		Order("version DESC").Limit(model.MaxRetainedModelVersions).
		Pluck("version", &keep).Error
	if err != nil || len(keep) == 0 {
		return
	}
	err = d.db.Where("model_name = ? AND version NOT IN ? AND active = ?",
		modelStateName, keep, false).
		Delete(&model.AnomalyModelVersion{}).Error
	if err != nil {
		d.logger.Warn("清理历史模型版本失败", zap.Error(err))
	}
}

// LoadActiveModel 启动时加载生效版本的模型。
//
// 恢复失败不阻断启动，但必须留下明确日志：静默地以「无模型」启动，
// 意味着要等一个完整重训周期才恢复评分能力，而外部看不出区别。
func (d *Detector) LoadActiveModel() {
	if d.db == nil {
		return
	}
	var v model.AnomalyModelVersion
	err := d.db.Where("model_name = ? AND active = ?", modelStateName, true).
		Order("version DESC").First(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		d.logger.Info("未找到生效的模型版本，将在样本积累后重新训练")
		return
	}
	if err != nil {
		d.logger.Warn("读取生效模型版本失败，本次以未训练状态启动", zap.Error(err))
		return
	}
	if err := d.forest.UnmarshalForest([]byte(v.Payload)); err != nil {
		// 加载失败保持未训练，不装载可疑模型：半个森林照样给分，只是分数无意义。
		d.logger.Warn("加载模型失败，保持未训练状态（等待重新训练）",
			zap.Int("version", v.Version), zap.Error(err))
		return
	}
	anomalyModelVersion.Set(float64(v.Version))
	d.logger.Info("已恢复模型",
		zap.Int("version", v.Version),
		zap.Int("samples", v.Samples))
}

// ListModelVersions 列出可回滚的模型版本。
func (d *Detector) ListModelVersions() ([]model.AnomalyModelVersion, error) {
	if d.db == nil {
		return nil, errors.New("未配置数据库")
	}
	var out []model.AnomalyModelVersion
	err := d.db.Select("id, model_name, version, samples, max_drift_sigma, active, rolled_back_from, created_at").
		Where("model_name = ?", modelStateName).
		Order("version DESC").Find(&out).Error
	return out, err
}

// RollbackModel 回滚到指定版本并立即生效。
//
// 回滚不设任何门槛：需要回滚时通常正在出问题，这时候要求先提交证据
// 等于把补救手段锁在故障后面。
func (d *Detector) RollbackModel(version int, actor string) error {
	if d.db == nil {
		return errors.New("未配置数据库")
	}
	var v model.AnomalyModelVersion
	err := d.db.Where("model_name = ? AND version = ?", modelStateName, version).First(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("模型版本 %d 不存在", version)
	}
	if err != nil {
		return err
	}

	// 先在内存里换上，确认能用，再改数据库的生效标记。
	// 顺序反过来的话，一个装不上的模型会被标成生效，重启后同样装不上——
	// 一次失败的回滚会变成持续的故障。
	if err := d.forest.UnmarshalForest([]byte(v.Payload)); err != nil {
		return fmt.Errorf("模型版本 %d 无法加载，已放弃回滚（当前模型未变）: %w", version, err)
	}

	from := d.activeVersion()
	err = d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.AnomalyModelVersion{}).
			Where("model_name = ? AND active = ?", modelStateName, true).
			Update("active", false).Error; err != nil {
			return err
		}
		return tx.Model(&model.AnomalyModelVersion{}).
			Where("model_name = ? AND version = ?", modelStateName, version).
			Updates(map[string]any{"active": true, "rolled_back_from": from}).Error
	})
	if err != nil {
		return fmt.Errorf("回滚标记写入失败（内存模型已切换，重启后会回到旧版本）: %w", err)
	}

	anomalyModelVersion.Set(float64(version))
	d.logger.Warn("模型已回滚",
		zap.Int("to_version", version),
		zap.Int("from_version", from),
		zap.String("actor", actor))
	return nil
}

// activeVersion 返回当前生效版本号，查不到返回 0。
func (d *Detector) activeVersion() int {
	var v model.AnomalyModelVersion
	if err := d.db.Select("version").
		Where("model_name = ? AND active = ?", modelStateName, true).
		First(&v).Error; err != nil {
		return 0
	}
	return v.Version
}
