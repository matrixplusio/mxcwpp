package migration

import (
	"errors"
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// criticalDeniedRules 是初始清单里不予 critical 准入的内置规则（按规则名），值为原因。
//
// 共同点是单个信号不够特异：同样的事件，日常运维与攻击都会产生。
// 它们照常告警，只是最高到 high；与别的信号关联成事件后仍会升上去。
var criticalDeniedRules = map[string]string{
	"sudoers 文件修改":             "配置管理与云厂商的主机代理会成批改写 sudoers，只凭文件被改无法与提权植入区分",
	"持久化 - /etc/sudoers 修改":    "配置管理与云厂商的主机代理会成批改写 sudoers，只凭文件被改无法与提权植入区分",
	"反弹 Shell - bash /dev/tcp": "运维脚本常用 /dev/tcp 做端口探活，单条命令行不足以认定是反弹 Shell",
	"影响 - Linux 备份/快照删除":       "例行的备份轮转同样会删除旧快照",
	"发现 - 云元数据接口访问":            "云主机上的代理与 SDK 会常规访问元数据接口",
	"Agent 规则命中 - Critical 级别": "原样透传 Agent 侧规则的级别，没有经过服务端的任何复核",
}

// criticalDeniedSequenceRules 同上，攻击链规则。
var criticalDeniedSequenceRules = map[string]string{
	"内存执行-外联 攻击链": "两步都是常见行为，按现有步骤条件组合起来误报仍然很高，待收窄后再恢复",
}

// criticalStageRules 是硬编码检测阶段里会产生 critical 的规则 ID，初始全部准入。
//
// 这里漏登一条，那条规则的告警就只能到 high。新增会出 critical 的硬编码规则时要同步加上。
var criticalStageRules = []string{
	"ROOTKIT_BACKDOOR",
	"ROOTKIT_KMOD_HIDDEN",
	"ROOTKIT_KNOWN_LKM",
	"PRIVILEGE_ESCALATION",
	"PRIV_UID0_GAIN",
	"PRIV_MOUNT_ESCAPE",
	"PRIV_KMOD_ROOTKIT",
	"REVERSE_SHELL",
	"WEBSHELL_HEURISTIC",
	"JAVA_MEMSHELL",
	"ioc-hash",
}

const criticalSeedReason = "初始清单：沿用规则声明的级别"

const (
	criticalSeedMarkerKey      = "critical_admissions_seeded_v1"
	criticalSeedMarkerCategory = "migration"
)

// seedCriticalAdmissions 写入 critical 准入的初始清单。成功写完一次之后不再执行。
//
// 「写完」用单独的标记判断，不用「表里有没有行」：内置规则的导入失败只记日志、不中断启动，
// 那种情况下这里只写得进几条硬编码规则，表却不再为空——之后永远不会补，
// 所有内置的 critical 规则被悄悄压到 high。所以规则表里一条 critical 规则都没有时不落标记，
// 下次启动再来；已有的记录不覆盖（人改过的保持原样）。
//
// 初始清单 = 当时所有声明为 critical 的规则，减去上面点名的几条。没有命中记录的规则
// 无从判断它准不准，先沿用声明的级别，之后由研判结果决定去留（见 manager 的自动降级）。
// 这之后新增的规则不会自动进清单：新规则要先证明自己，才配得上最高级别。
func seedCriticalAdmissions(db *gorm.DB, logger *zap.Logger) error {
	var marker model.SystemConfig
	err := db.Where("`key` = ? AND category = ?", criticalSeedMarkerKey, criticalSeedMarkerCategory).First(&marker).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// 上一版没有标记、每次启动都按「表是否为空」判断。从那一版升上来时表里已经有清单：
	// 只补标记，不再插入——否则上次写入之后新建的 critical 规则会被自动准入，
	// 与「新规则要先证明自己」相反。
	// 「有清单」要看上一版有没有把规则表里的规则写进来：规则导入失败时它只写得进硬编码检测
	// 那几条，那是一份残缺的清单，照下面的流程补齐，不能就此盖章。只认初始写入的行——
	// 残缺清单上有人手工准入过一条规则，不代表其余的都登记过了。
	var existing int64
	if err := db.Model(&model.RuleCriticalAdmission{}).
		Where("changed_by = ? AND (rule_id LIKE ? OR rule_id LIKE ?)", model.AdmissionChangedBySeed, "cel-%", "seq-%").
		Count(&existing).Error; err != nil {
		return err
	}
	if existing > 0 {
		logger.Info("critical 准入清单已存在（上一版写入），只补完成标记", zap.Int64("rule_rows", existing))
		return db.Create(&model.SystemConfig{
			Key: criticalSeedMarkerKey, Category: criticalSeedMarkerCategory, Value: "done",
			Description: "critical 准入初始清单已写入",
		}).Error
	}

	now := model.Now()
	row := func(ruleID, deniedReason string) model.RuleCriticalAdmission {
		r := model.RuleCriticalAdmission{
			RuleID: ruleID, Allowed: true, Reason: criticalSeedReason,
			ChangedBy: model.AdmissionChangedBySeed, DecidedAt: now,
		}
		if deniedReason != "" {
			r.Allowed, r.Reason = false, deniedReason
		}
		return r
	}

	rows := make([]model.RuleCriticalAdmission, 0, 128)
	for _, id := range criticalStageRules {
		rows = append(rows, row(id, ""))
	}

	type named struct {
		ID   uint
		Name string
	}
	var cel, seq []named
	if err := db.Model(&model.DetectionRule{}).Select("id, name").
		Where("severity = ?", "critical").Find(&cel).Error; err != nil {
		return err
	}
	for _, r := range cel {
		rows = append(rows, row(fmt.Sprintf("cel-%d", r.ID), criticalDeniedRules[r.Name]))
	}
	if err := db.Model(&model.SequenceRule{}).Select("id, name").
		Where("severity = ?", "critical").Find(&seq).Error; err != nil {
		return err
	}
	for _, r := range seq {
		rows = append(rows, row(fmt.Sprintf("seq-%d", r.ID), criticalDeniedSequenceRules[r.Name]))
	}

	// 规则还没导入时什么都不写：表只要非空，引擎就认为清单已就绪，
	// 清单外的 critical 规则会全部被压到 high。空着，引擎不压级，下次启动再来。
	if len(cel) == 0 {
		logger.Warn("规则表里还没有 critical 规则，critical 准入初始清单暂不写入，下次启动再补")
		return nil
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(rows, 100).Error; err != nil {
			return err
		}
		return tx.Create(&model.SystemConfig{
			Key: criticalSeedMarkerKey, Category: criticalSeedMarkerCategory, Value: "done",
			Description: "critical 准入初始清单已写入",
		}).Error
	}); err != nil {
		return err
	}
	denied := 0
	for i := range rows {
		if !rows[i].Allowed {
			denied++
		}
	}
	logger.Info("critical 准入初始清单已写入", zap.Int("total", len(rows)), zap.Int("denied", denied))
	return nil
}
