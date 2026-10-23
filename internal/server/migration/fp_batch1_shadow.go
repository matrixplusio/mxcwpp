package migration

import (
	"errors"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// fpBatch1ShadowRules 退回影子阶段的规则。
//
// 这几条规则点名的就是日常进程（uname、ps、包管理器），只能靠「豁免的进程正是规则要
// 检测的进程」的白名单压住，规则名义上在告警、实际不出告警，而且没有地方显示这一点。
// engine 现在会拒绝这类白名单，规则若留在告警阶段，正常命中会全部回来。退回影子阶段：
// 命中照样计数，规则列表里如实显示「不告警」。
//   - 主机枚举、进程枚举：单个侦察命令正常系统每天都在跑，后续改为参与关联的信号；
//   - 容器内包管理器：服务端事件还没有容器字段，表达式在宿主机上同样命中。
var fpBatch1ShadowRules = []string{
	"信息收集 - 主机枚举",
	"信息收集 - 进程枚举",
	"容器内 - 包管理器执行",
}

const fpBatch1ShadowMarker = "rules_fp_batch1_shadow_v1"

// shadowFPBatch1Rules 只执行一次：之后人工晋级的规则不能在下次启动时又被按回去。
func shadowFPBatch1Rules(db *gorm.DB, logger *zap.Logger) error {
	var marker model.SystemConfig
	err := db.Where("`key` = ? AND category = ?", fpBatch1ShadowMarker, reactivationMarkerCategory).First(&marker).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.DetectionRule{}).
			Where("name IN ? AND builtin = ? AND user_modified = ? AND stage = ?",
				fpBatch1ShadowRules, true, false, model.RuleStageAlert).
			Update("stage", model.RuleStageShadow)
		if res.Error != nil {
			return res.Error
		}
		if err := tx.Create(&model.SystemConfig{
			Key: fpBatch1ShadowMarker, Category: reactivationMarkerCategory, Value: "done",
			Description: "点名日常进程的规则已退回影子阶段",
		}).Error; err != nil {
			return err
		}
		logger.Info("点名日常进程的规则已退回影子阶段", zap.Int64("rules", res.RowsAffected))
		return nil
	})
}
