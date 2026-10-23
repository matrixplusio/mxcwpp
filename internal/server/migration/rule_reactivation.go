package migration

import (
	"errors"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// reactivatedRules 是此前在绝大多数主机上不可能触发、这次才真正开始工作的内置规则。
//
// 两类原因：写文件的规则只认 file_write，而内核探针把带写意图的打开报成 file_open；
// 另一些规则在文件或网络事件上判断 exe / cmdline，这两个字段此前在这类事件里恒为空。
// 修好之后它们会第一次面对全量主机的真实流量，会响多少没有人知道。
var reactivatedRules = []string{
	"持久化 - systemd unit 创建",
	"持久化 - /etc/rc.local 修改",
	"持久化 - crontab 新增",
	"持久化 - .bashrc/.profile 修改",
	"K8s - kube-proxy 配置改写",
	"持久化 - /etc/passwd 直接写",
	"持久化 - /etc/sudoers 修改",
	"持久化 - SSH config Match 子句",
	"持久化 - PAM 模块替换",
	"反检测 - 隐藏文件大量创建",
	"影响 - 大量文件加密 (.locked/.encrypted)",
	"DNS 查询 - 可疑进程",
	"C2 - DNS over HTTPS (DoH) C2",
	"容器 - core_pattern 修改逃逸",
	"影响 - 勒索常见加密扩展名",
	"初始访问 - Kubernetes API 8080 未授权",
	// 表达式里没有直接写 exe，靠的是「这个程序是第一次出现」：网络事件补上程序信息之前，
	// 这个判断对它们恒为假。恢复后命中的多是常驻的系统代理在 engine 重启后的「首次」。
	"新出现进程外网连接",
}

const (
	reactivationMarkerKey      = "rules_reactivated_to_shadow_v1"
	reactivationMarkerCategory = "migration"
)

// shadowReactivatedRules 把上面这些规则退回影子阶段，只执行一次。
//
// 影子阶段只记命中量、不告警。先看它们在真实流量上会响多少次，再由人逐条晋级；
// 直接放在告警阶段，等于拿告警接收人去做这次测量。
// 只做一次：之后人工晋级过的规则，不能在下次启动时又被按回去。
func shadowReactivatedRules(db *gorm.DB, logger *zap.Logger) error {
	var marker model.SystemConfig
	err := db.Where("`key` = ? AND category = ?", reactivationMarkerKey, reactivationMarkerCategory).First(&marker).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&model.DetectionRule{}).
			Where("name IN ? AND builtin = ? AND user_modified = ? AND stage = ?",
				reactivatedRules, true, false, model.RuleStageAlert).
			Update("stage", model.RuleStageShadow)
		if res.Error != nil {
			return res.Error
		}
		if err := tx.Create(&model.SystemConfig{
			Key: reactivationMarkerKey, Category: reactivationMarkerCategory, Value: "done",
			Description: "此前无法触发的内置规则已退回影子阶段观察",
		}).Error; err != nil {
			return err
		}
		logger.Info("此前无法触发的内置规则已退回影子阶段", zap.Int64("rules", res.RowsAffected))
		return nil
	})
}
