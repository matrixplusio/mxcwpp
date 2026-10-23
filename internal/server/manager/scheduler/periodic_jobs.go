package scheduler

import (
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/detquality"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

// 任务 Key。Key 存在数据库里，改名等于新建一个任务、丢掉原来的排期。
const (
	JobVulnPrecheck      = "vuln_precheck"
	JobVulnFPCleanup     = "vuln_fp_full_cleanup"
	JobMySQLRetention    = "mysql_retention"
	JobBaselineMaint     = "baseline_maintenance"
	JobVirusDBCheck      = "virus_db_check"
	JobNVDEnrich         = "nvd_enrich"
	JobKubeBaselineScan  = "kube_baseline_rescan"
	JobAutoTuning        = "auto_tuning"
	JobCriticalAdmission = "critical_admission"
)

// RegisterBuiltinJobs 登记只依赖数据库的任务。
// 依赖其它对象的（预检、病毒库、漏洞补充信息、K8s 基线）由构造那些对象的地方登记。
//
// 默认时刻的排法：会压数据库的错开放在凌晨，避开 02:00 的漏洞库同步与 03:00 的情报同步；
// 一天一轮够用的不再一天跑几轮。都只是默认值，控制台可改。
func RegisterBuiltinJobs(r *JobRunner, db *gorm.DB, logger *zap.Logger) {
	r.Register(PeriodicJob{
		Key: JobVulnFPCleanup, Name: "漏洞误报全量清理",
		Description:          "全量核对主机漏洞关联，清掉主机换系统、卸载软件后已不成立的关联。每次漏洞入库后的增量清理不受这里影响。",
		DefaultIntervalHours: 24, DefaultStartHour: 5,
		Run: func(context.Context) error {
			advisory.CleanupHostVulnFPScoped(db, logger, advisory.CleanupScope{Full: true})
			advisory.CleanupAlreadyPatched(db, logger)
			return nil
		},
	})
	r.Register(PeriodicJob{
		Key: JobMySQLRetention, Name: "保留期清理",
		Description:          "按各表的保留天数删除 MySQL 里过期的历史数据。保留天数在「数据保留」里设置。",
		DefaultIntervalHours: 24, DefaultStartHour: 6,
		Run: func(context.Context) error { processMySQLRetention(db, logger); return nil },
	})
	r.Register(PeriodicJob{
		Key: JobBaselineMaint, Name: "行为基线维护",
		Description:          "清理已不存在主机的行为基线、过期的行为偏离记录和基线扫描历史。",
		DefaultIntervalHours: 24, DefaultStartHour: 7,
		Run: func(context.Context) error { processBaselineMaintenance(db, logger); return nil },
	})
	r.Register(PeriodicJob{
		Key: JobAutoTuning, Name: "自动调优聚合",
		Description:          "汇总被反复判为误报的告警模式，生成白名单建议供人工采纳。",
		DefaultIntervalHours: 6, DefaultStartHour: 0,
		Run: func(context.Context) error { processAutoTuning(db, logger); return nil },
	})
	r.Register(PeriodicJob{
		Key: JobCriticalAdmission, Name: "critical 准入复核",
		Description:          "对被判成误报的次数够多、且没有一条真实威胁的规则，提出移出 critical 准入的建议并通知，由人确认。",
		DefaultIntervalHours: 24, DefaultStartHour: 8,
		Run: func(context.Context) error {
			return runCriticalAdmissionReview(detquality.NewService(db, logger), logger)
		},
	})
	r.Register(PeriodicJob{
		Key: model.JobKeyAlertDigest, Name: "未处理告警日报",
		Description:          "每天汇总超过 24 小时仍未处理的告警，发到通知渠道。",
		DefaultIntervalHours: 24, DefaultStartHour: model.DefaultAlertDigestHour,
		FixedInterval: true, External: true,
	})
}

// 需要较长执行时间的任务的超时。
const (
	// JobTimeoutPrecheck 预检巡检逐台串行下发，主机多时一轮要几十分钟。
	JobTimeoutPrecheck = 4 * time.Hour
	// JobTimeoutNVD 无 API key 时每次请求间隔数秒，积压多时一轮很长。
	JobTimeoutNVD = 6 * time.Hour
)
