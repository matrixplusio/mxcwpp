// Package migration 提供数据库迁移功能
package migration

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

// Migrate 执行数据库迁移
func Migrate(db *gorm.DB, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Info("开始数据库迁移")

	// 处理组件表的迁移问题（旧数据可能没有有效的外键）
	if err := migrateComponentTables(db, logger); err != nil {
		logger.Warn("组件表迁移处理", zap.Error(err))
	}

	// 执行自动迁移（带连接恢复和重试）
	for _, m := range model.AllModels {
		var migrateErr error
		for attempt := range 3 {
			if attempt > 0 {
				// 重试前必须真正清空连接池，否则重试拿到的还是那个已失效的连接。
				//
				// 原写法用 SetConnMaxLifetime(0)，注释说"强制回收旧连接"，但 database/sql
				// 里 0 表示连接**永不因年龄被关闭**——语义正好相反，池子一条都没清掉。
				// 实测：大表 ALTER（如 incidents 加列）结束后连接被服务端断开，
				// 下一个模型迁移报 "invalid connection"，三次重试都在 1ms 内以同样方式失败，
				// manager 直接 fatal 退出。表越大越容易触发。
				//
				// 用极小的 lifetime 让池中所有连接立即到期被关闭，Ping 建立新连接后再恢复。
				if sqlDB, err := db.DB(); err == nil {
					sqlDB.SetConnMaxLifetime(time.Nanosecond)
					_ = sqlDB.Ping()
					sqlDB.SetConnMaxLifetime(time.Hour)
				}
				logger.Info("重试迁移", zap.String("model", fmt.Sprintf("%T", m)), zap.Int("attempt", attempt+1))
			}
			if migrateErr = db.AutoMigrate(m); migrateErr == nil {
				break
			}
		}
		if migrateErr != nil {
			logger.Error("数据库迁移失败", zap.Error(migrateErr), zap.String("model", fmt.Sprintf("%T", m)))
			return fmt.Errorf("迁移模型 %T 失败: %w", m, migrateErr)
		}
		logger.Info("模型迁移成功", zap.String("model", fmt.Sprintf("%T", m)))
	}

	// 执行数据迁移：扩展资产表 ID 列（GORM AutoMigrate 不一定会自动扩展已有列的长度）
	if err := migrateAssetTableIDColumns(db, logger); err != nil {
		logger.Warn("资产表ID列扩展处理", zap.Error(err))
	}

	// 执行数据迁移：扩展 alerts 表 result_id 列
	if err := migrateAlertResultIDColumn(db, logger); err != nil {
		logger.Warn("告警表result_id列扩展处理", zap.Error(err))
	}

	// 执行数据迁移：扩展 incidents 表 incident_id 列
	if err := migrateIncidentIDColumn(db, logger); err != nil {
		logger.Warn("事件表incident_id列扩展处理", zap.Error(err))
	}

	// 执行数据迁移：scan_results / fix_results 主键从 result_id 迁移到复合主键
	if err := migrateScanResultsCompositeKey(db, logger); err != nil {
		logger.Warn("scan_results 复合主键迁移处理", zap.Error(err))
	}

	// 创建 scan_results dashboard 复合索引（host_id, rule_id, checked_at），加速窗口函数查询
	if err := ensureScanResultsDashboardIndex(db, logger); err != nil {
		logger.Warn("scan_results dashboard 索引创建失败", zap.Error(err))
	}

	// 执行数据迁移：为现有数据设置默认的运行时类型
	if err := migrateRuntimeTypes(db, logger); err != nil {
		logger.Warn("运行时类型迁移处理", zap.Error(err))
	}

	// 执行数据迁移：更新策略组名称为主机系统基线组
	if err := migratePolicyGroupName(db, logger); err != nil {
		logger.Warn("策略组名称迁移处理", zap.Error(err))
	}

	// 一次性回填：历史内置基线策略/规则标记 builtin=true（builtin 为本版本新增字段）
	if err := migrateBaselineBuiltinFlag(db, logger); err != nil {
		logger.Warn("基线 builtin 回填处理", zap.Error(err))
	}

	// 执行数据迁移：为通知配置设置 notify_category
	if err := migrateNotificationCategory(db, logger); err != nil {
		logger.Warn("通知类别迁移处理", zap.Error(err))
	}

	// 执行数据迁移：为告警记录回填 source 字段
	if err := migrateAlertSource(db, logger); err != nil {
		logger.Warn("告警来源迁移处理", zap.Error(err))
	}

	// 执行数据迁移：sensor → edr 重命名
	if err := migrateSensorToEDR(db, logger); err != nil {
		logger.Warn("sensor→edr 迁移处理", zap.Error(err))
	}

	// 清理废弃的 edr 插件和 tetragon 依赖（EDR 已内置 Agent v1.2.0+）
	if err := migrateRemoveEDRPlugin(db, logger); err != nil {
		logger.Warn("edr 插件清理处理", zap.Error(err))
	}

	// 回滚之前过激 soft delete 误删的真 CVE
	if err := migrateRestoreErroneouslyDeletedVulns(db, logger); err != nil {
		logger.Warn("回滚误删 vuln 失败", zap.Error(err))
	}
	// 标记历史 nvd/osv/redhat 数据为 confidence=low（不删除，仅 UI 过滤）
	if err := migrateMarkFakeVulns(db, logger); err != nil {
		logger.Warn("历史 vuln confidence 标记", zap.Error(err))
	}

	// 添加性能优化索引（幂等）
	if err := AddPerformanceIndexes(db, logger); err != nil {
		logger.Warn("添加性能索引失败", zap.Error(err))
	}

	// 回填历史 vuln 的 vuln_category / restart_action（P5）
	if err := migrateCategorizeExistingVulns(db, logger); err != nil {
		logger.Warn("漏洞分类回填失败", zap.Error(err))
	}

	// 回填 host_vulnerabilities.asset_type / fix_owner(P-vuln-classify)
	// 全表 join software 推导,首次部署后单次跑一致即可,后续写入路径由 BeforeSave 自动维护
	// 走异步,避免阻塞 manager 启动(prod 11k+ host_vuln × software join 耗时)
	go func() {
		if err := BackfillAssetTypeAndFixOwner(db, logger); err != nil {
			logger.Warn("host_vuln asset_type 回填失败(异步)", zap.Error(err))
		} else {
			logger.Info("host_vuln asset_type 异步回填完成")
		}
	}()

	// 修历史 vuln source 字段被 OS source 错误覆盖（OSV 写入后 debian-tracker 覆盖）
	// 需放在 CleanupHostVulnFP 之前，否则 cleanup 会把 OSV 命中的 host_vuln 误删
	if err := migrateFixOverwrittenEcosystemSource(db, logger); err != nil {
		logger.Warn("vuln source 字段修复失败", zap.Error(err))
	}

	// 清理 v2.5.0 之前 ScanAll 留下的跨 OS host_vuln 误报 + OSS-Fuzz 噪音
	// 改为后台 goroutine 跑:涉及 host_vulnerabilities × software 60M+ 行 JOIN,
	// 单次 cleanup 60-90s,会阻塞 HTTP server 启动 → manager unhealthy。
	// 这是 housekeeping 数据修复,无业务实时性要求,后台跑即可。
	go func() {
		if err := migrateCleanupLegacyHostVuln(db, logger); err != nil {
			logger.Warn("legacy host_vuln 清理失败(异步)", zap.Error(err))
		} else {
			logger.Info("legacy host_vuln 异步清理完成")
		}
	}()

	// 扩 advisory_packages.source_advisory_id varchar(64)→255（Alpine 拼接 ID 易超 64）
	if err := migrateAdvisoryPackagesSourceAdvisoryID(db, logger); err != nil {
		logger.Warn("advisory_packages source_advisory_id 扩列失败", zap.Error(err))
	}

	// 创建 advisory_packages 唯一组合索引（GORM AutoMigrate 不创建多列 UNIQUE）
	if err := ensureAdvisoryPackagesIndex(db, logger); err != nil {
		logger.Warn("advisory_packages 唯一索引创建失败", zap.Error(err))
	}

	// 修 host_isolations.host_id 旧版 UNIQUE 索引 → 普通索引.
	// 旧表 idx_host_isolations_host_id UNIQUE 阻止同主机第二次 isolate (Error 1062), 转事件流模型.
	if err := dropHostIsolationsHostIDUnique(db, logger); err != nil {
		logger.Warn("host_isolations.host_id UNIQUE 索引修复失败", zap.Error(err))
	}

	// 从 vulnerabilities.fixed_version 回填 advisory_packages（仅首次空表时跑）
	if err := backfillAdvisoryPackages(db, logger); err != nil {
		logger.Warn("advisory_packages 回填失败", zap.Error(err))
	}

	// 把低保真单信号噪声规则降级（fidelity=low），不独立告警，仅喂关联（CrowdStrike IOA 模型）
	if err := migrateMarkLowFidelityRules(db, logger); err != nil {
		logger.Warn("低保真规则降级失败", zap.Error(err))
	}

	// 把纯端口启发式 C2 规则降级为 indicator（fidelity=low），生产 proxy/CDN 正常出站误报刷屏
	if err := migrateMarkPortHeuristicLowFidelity(db, logger); err != nil {
		logger.Warn("端口启发式规则降级失败", zap.Error(err))
	}

	// behavior_alerts 存量去重 + 唯一索引，让 BDE 落库改 upsert(同 host+metric 累加 hit_count 不新增行)
	if err := migrateBehaviorAlertDedup(db, logger); err != nil {
		logger.Warn("behavior_alerts 去重/唯一索引失败", zap.Error(err))
	}

	// anomaly_alerts 存量去重 + 唯一索引，让 ML 异常引擎落库改 upsert
	// (同 host+alert_type+pattern+top_metric 累加 hit_count 不新增行，根治 c2_beacon 刷屏)。
	// 迁移失败不静默 Warn 掩盖：记 Error 明示 —— 缺唯一索引会让 upsert 退化成刷屏，
	// 检测器 VerifySchema 会因索引缺失判定 schema 未就绪并 fail-closed（落库模式降级 shadow，只观测不落库）。
	if err := migrateAnomalyAlertDedup(db, logger); err != nil {
		logger.Error("anomaly_alerts 去重/唯一索引迁移失败：检测器将因 schema 未就绪 fail-closed 降级 shadow（只观测不落库）", zap.Error(err))
	}

	// 合并三条重复的 touch 时间戳篡改规则(同 T1070.006 三重告警)，禁用冗余两条
	if err := migrateDedupTimestampRules(db, logger); err != nil {
		logger.Warn("合并重复时间戳规则失败", zap.Error(err))
	}

	// 给存量检测规则回填 detect-only 观察期起点 effective_at = created_at
	if err := migrateBackfillRuleEffectiveAt(db, logger); err != nil {
		logger.Warn("回填规则 effective_at 失败", zap.Error(err))
	}
	if err := migrateBackfillRuleStage(db, logger); err != nil {
		logger.Warn("检测规则生命周期阶段回填处理", zap.Error(err))
	}

	// 种入内置多步攻击链(序列)规则：序列引擎已实现但表空,补齐 IOA 攻击链检测
	if err := seedBuiltinSequenceRules(db, logger); err != nil {
		logger.Warn("内置序列规则种入失败", zap.Error(err))
	}

	logger.Info("数据库迁移完成")
	return nil
}

// migrateBackfillRuleEffectiveAt 给存量检测规则回填 effective_at = created_at。
//
// detect-only 上线观察期(P3)新增 effective_at 列：新规则上线起 ruleGraceWindow 内降级 indicator。
// 存量规则早已上线、不应进入观察期，回填为创建时间使其立即过窗，避免加列后全量规则被静默。
// migrateBackfillRuleStage 为存量规则回填生命周期阶段。
//
// 存量规则一律置为 alert，保持它们迁移前的行为。
//
// 这个方向不能反：新加的阶段字段若让存量规则落到 shadow，整个已部署的规则集
// 会在一次升级后集体停止告警——平台看起来一切正常，实际已经不再报警。
// 宁可让存量规则维持现状再逐条降级，也不能靠一次迁移把检测能力清零。
func migrateBackfillRuleStage(db *gorm.DB, logger *zap.Logger) error {
	r := db.Model(&model.DetectionRule{}).
		Where("stage IS NULL OR stage = ''").
		Update("stage", model.RuleStageAlert)
	if r.Error != nil {
		return r.Error
	}
	if r.RowsAffected > 0 {
		logger.Info("已为存量检测规则回填生命周期阶段",
			zap.Int64("count", r.RowsAffected),
			zap.String("stage", model.RuleStageAlert))
	}
	return nil
}

// 幂等：仅回填 NULL（AutoMigrate 新加列对存量行为 NULL；新增规则由 BeforeCreate 置当前时间）。
func migrateBackfillRuleEffectiveAt(db *gorm.DB, logger *zap.Logger) error {
	r := db.Exec("UPDATE detection_rules SET effective_at = created_at WHERE effective_at IS NULL")
	if r.Error != nil {
		return r.Error
	}
	if r.RowsAffected > 0 {
		logger.Info("回填检测规则 effective_at", zap.Int64("count", r.RowsAffected))
	}
	return nil
}

// migrateMarkLowFidelityRules 把繁忙业务负载上必然刷屏、单信号、近零真阳价值的检测规则
// 标记为 fidelity=low（降级 indicator，不独立告警，事件仍喂 anomaly/storyline 关联）。
//
// 依据：高频外连 / DNS / 枚举 / tmp / 隐藏文件 等单信号规则在
// db/mq/zookeeper/网关等正常业务上持续触发。对齐 Falco「少量精调规则 > 一堆噪声规则」+
// CrowdStrike IOA「单信号不告警，多信号关联才告警」。幂等。
//
// 仅降级"低保真"规则名模式；高保真规则(反弹shell/CobaltStrike/memfd/真C2/横向)保持 high。
func migrateMarkLowFidelityRules(db *gorm.DB, logger *zap.Logger) error {
	var total int64

	// 1) 类目驱动降级：整个噪声类目单信号、繁忙业务上必然刷屏、近零真阳价值。
	//    - network_scan：入站扫描/探测规则(tcp_accept 单事件，每次合法连接即命中)。
	//    - discovery：主机/网络/用户/进程枚举、云元数据探测等单信号。
	//    比按规则名逐条匹配更彻底(name-pattern 曾漏掉 network_scan 全部入站规则)。
	//    保留 user_modified=true 的规则（用户显式设过 fidelity 则不覆盖）。
	rc := db.Model(&model.DetectionRule{}).
		Where("category IN ? AND fidelity <> ? AND user_modified = ?",
			noiseFidelityCategories, model.RuleFidelityLow, false).
		Update("fidelity", model.RuleFidelityLow)
	if rc.Error != nil {
		return rc.Error
	}
	total += rc.RowsAffected

	// 2) 跨类目单信号噪声规则名模式（属 execution/defense_evasion 等类，非 1) 的噪声类目，仍需按名匹配）。
	lowFidelityPatterns := []string{
		"高频外连%",
		"/tmp 目录可执行文件创建%",
		"反检测 - 隐藏文件大量创建%",
	}
	for _, p := range lowFidelityPatterns {
		r := db.Model(&model.DetectionRule{}).
			Where("name LIKE ? AND fidelity <> ? AND user_modified = ?", p, model.RuleFidelityLow, false).
			Update("fidelity", model.RuleFidelityLow)
		if r.Error != nil {
			return r.Error
		}
		total += r.RowsAffected
	}
	if total > 0 {
		logger.Info("已降级低保真噪声规则为 indicator", zap.Int64("count", total))
	}
	return nil
}

// noiseFidelityCategories 是整类降级为 fidelity=low 的噪声检测类目。
// 单信号、无上下文、在正常业务负载上持续刷屏，价值仅在多信号关联，故降为 indicator。
var noiseFidelityCategories = []string{"network_scan", "discovery"}

// migrateMarkPortHeuristicLowFidelity 把纯端口启发式 C2 检测规则标记为 fidelity=low（降级 indicator，
// 不独立告警，事件仍喂 anomaly/storyline 关联）。
//
// 依据：这类规则仅按 remote_port 命中高危端口/CobaltStrike默认端口/VPN/IRC/Tor/SOCKS/矿池端口，
// 对 proxy/CDN/正常业务出站流量误报刷屏（全队列 197-228 台均匀铺满 = 环境噪声铁证）。端口本身零上下文，
// 单信号价值极低；降级后仅参与多信号关联，真行为检测（memfd 反弹shell / 真信标模式 / 挖矿进程行为）保 high 不动。
// 幂等：按规则名精确匹配，已 low 则跳过。
func migrateMarkPortHeuristicLowFidelity(db *gorm.DB, logger *zap.Logger) error {
	portHeuristicRules := []string{
		"高危端口外连",
		"IRC 协议外连",
		"Tor/匿名代理外连",
		"挖矿矿池端口外连",
		"SOCKS 代理外连",
		"VPN 端口外连",
		"Cobalt Strike 默认端口",
	}
	r := db.Model(&model.DetectionRule{}).
		Where("name IN ? AND fidelity <> ?", portHeuristicRules, model.RuleFidelityLow).
		Update("fidelity", model.RuleFidelityLow)
	if r.Error != nil {
		return r.Error
	}
	if r.RowsAffected > 0 {
		logger.Info("已降级端口启发式 C2 规则为 indicator", zap.Int64("count", r.RowsAffected))
	}
	return nil
}

// migrateDedupTimestampRules 合并三条重复的 T1070.006 touch 时间戳篡改规则：
// "防御规避 - 时间戳伪造" / "防御绕过 - timestamp tamper" / "防御逃避 - timestomp 篡改文件时间"
// 都检测同一 touch -t/-r/-d 事件，命中会三重告警。保留第一条并补全 -d/--date 覆盖，禁用另两条。
// 幂等；user_modified=true 的规则不覆盖（尊重用户自定义）。
func migrateDedupTimestampRules(db *gorm.DB, logger *zap.Logger) error {
	redundant := []string{"防御绕过 - timestamp tamper", "防御逃避 - timestomp 篡改文件时间"}
	r := db.Model(&model.DetectionRule{}).
		Where("name IN ? AND enabled = ? AND user_modified = ?", redundant, true, false).
		Update("enabled", false)
	if r.Error != nil {
		return r.Error
	}
	// 保留规则补全 -d/--date 覆盖（原表达式缺，去重后由它统一覆盖）。
	merged := `exe.contains("touch") && (cmdline.contains("-t") || cmdline.contains("-r") || cmdline.contains("-d") || cmdline.contains("--reference") || cmdline.contains("--date"))`
	if err := db.Model(&model.DetectionRule{}).
		Where("name = ? AND user_modified = ?", "防御规避 - 时间戳伪造", false).
		Update("expression", merged).Error; err != nil {
		return err
	}
	if r.RowsAffected > 0 {
		logger.Info("合并重复时间戳篡改规则", zap.Int64("disabled", r.RowsAffected))
	}
	return nil
}

// behaviorAlertDedupIndex 是 behavior_alerts 的 (tenant_id, host_id, metric) 唯一索引名。
const behaviorAlertDedupIndex = "ux_behavior_alerts_host_metric"

// anomalyAlertDedupIndex 是 anomaly_alerts 的去重唯一索引名。
const anomalyAlertDedupIndex = "ux_anomaly_alerts_dedup"

// migrateAnomalyAlertDedup 为 anomaly_alerts 建 (tenant_id, host_id, alert_type, pattern_name, top_metric)
// 唯一索引，让 ML 异常引擎落库改 upsert（同键复发累加 hit_count，不新增行、不覆盖已处置 status）。
// 根治 c2_beacon 每次触发新建一行的刷屏，并修掉旧 dedup"标 false_positive 反被解封重报"的缺陷。
func migrateAnomalyAlertDedup(db *gorm.DB, logger *zap.Logger) error {
	hasIndex := db.Migrator().HasIndex(&model.AnomalyAlert{}, anomalyAlertDedupIndex)
	var nullKeyRows int64
	if err := db.Model(&model.AnomalyAlert{}).
		Where("tenant_id IS NULL OR host_id IS NULL OR alert_type IS NULL OR pattern_name IS NULL OR top_metric IS NULL").
		Count(&nullKeyRows).Error; err != nil {
		return fmt.Errorf("anomaly_alerts 历史 NULL 键检查失败: %w", err)
	}
	// 已有唯一索引仍可能含多条 NULL 键（MySQL UNIQUE 允许多个 NULL）。为安全归一化，
	// 仅在确有 NULL 键时临时移除索引；任一步失败都会被 runtime schema gate 降级为 shadow。
	if hasIndex && nullKeyRows > 0 {
		if err := db.Migrator().DropIndex(&model.AnomalyAlert{}, anomalyAlertDedupIndex); err != nil {
			return fmt.Errorf("anomaly_alerts 临时移除旧唯一索引失败: %w", err)
		}
		hasIndex = false
	}

	// 先把历史 NULL 去重键归一化。MySQL UNIQUE 允许多个 NULL，且 NULL = NULL 不成立；
	// 不归一化会导致旧行无法合并、后续 upsert 也永远命不中旧行。
	for _, stmt := range []string{
		"UPDATE anomaly_alerts SET tenant_id = 't-default' WHERE tenant_id IS NULL OR tenant_id = ''",
		"UPDATE anomaly_alerts SET host_id = '' WHERE host_id IS NULL",
		"UPDATE anomaly_alerts SET alert_type = '' WHERE alert_type IS NULL",
		"UPDATE anomaly_alerts SET pattern_name = '' WHERE pattern_name IS NULL",
		"UPDATE anomaly_alerts SET top_metric = '' WHERE top_metric IS NULL",
		"UPDATE anomaly_alerts SET hit_count = 1 WHERE hit_count IS NULL OR hit_count < 1",
		"UPDATE anomaly_alerts SET last_seen_at = COALESCE(last_seen_at, updated_at, created_at, CURRENT_TIMESTAMP) WHERE last_seen_at IS NULL",
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("anomaly_alerts 历史字段归一化失败: %w", err)
		}
	}

	if hasIndex {
		return nil
	}

	// 存量去重仅在 MySQL 上执行（sqlite 测试环境无存量）。保留每组最小 id，hit_count 置为组行数。
	if db.Dialector.Name() == "mysql" {
		if err := db.Exec(`
UPDATE anomaly_alerts a
JOIN (
	SELECT MIN(id) AS keep_id, SUM(GREATEST(hit_count, 1)) AS cnt, MAX(last_seen_at) AS last_seen
	FROM anomaly_alerts
	GROUP BY tenant_id, host_id, alert_type, pattern_name, top_metric
) g ON a.id = g.keep_id
SET a.hit_count = g.cnt, a.last_seen_at = g.last_seen`).Error; err != nil {
			return fmt.Errorf("anomaly_alerts 累加 hit_count 失败: %w", err)
		}
		r := db.Exec(`
DELETE a FROM anomaly_alerts a
JOIN (
	SELECT MIN(id) AS keep_id, tenant_id, host_id, alert_type, pattern_name, top_metric
	FROM anomaly_alerts
	GROUP BY tenant_id, host_id, alert_type, pattern_name, top_metric
) g ON a.tenant_id = g.tenant_id AND a.host_id = g.host_id AND a.alert_type = g.alert_type
	AND a.pattern_name = g.pattern_name AND a.top_metric = g.top_metric
WHERE a.id <> g.keep_id`)
		if r.Error != nil {
			return fmt.Errorf("anomaly_alerts 删除重复行失败: %w", r.Error)
		}
		if r.RowsAffected > 0 {
			logger.Info("anomaly_alerts 存量去重", zap.Int64("removed", r.RowsAffected))
		}
	} else if db.Dialector.Name() == "sqlite" {
		// SQLite 仅用于本地/测试，但仍完整验证历史归一化 + 去重契约。
		if err := db.Exec(`
UPDATE anomaly_alerts AS a
SET hit_count = (
	SELECT COALESCE(SUM(CASE WHEN b.hit_count < 1 THEN 1 ELSE b.hit_count END), 1) FROM anomaly_alerts AS b
	WHERE b.tenant_id = a.tenant_id AND b.host_id = a.host_id AND b.alert_type = a.alert_type
		AND b.pattern_name = a.pattern_name AND b.top_metric = a.top_metric
), last_seen_at = (
	SELECT MAX(b.last_seen_at) FROM anomaly_alerts AS b
	WHERE b.tenant_id = a.tenant_id AND b.host_id = a.host_id AND b.alert_type = a.alert_type
		AND b.pattern_name = a.pattern_name AND b.top_metric = a.top_metric
)`).Error; err != nil {
			return fmt.Errorf("anomaly_alerts sqlite 累加 hit_count 失败: %w", err)
		}
		if err := db.Exec(`
DELETE FROM anomaly_alerts
WHERE id NOT IN (
	SELECT MIN(id) FROM anomaly_alerts
	GROUP BY tenant_id, host_id, alert_type, pattern_name, top_metric
)`).Error; err != nil {
			return fmt.Errorf("anomaly_alerts sqlite 删除重复行失败: %w", err)
		}
	}

	if err := db.Exec("CREATE UNIQUE INDEX " + anomalyAlertDedupIndex +
		" ON anomaly_alerts (tenant_id, host_id, alert_type, pattern_name, top_metric)").Error; err != nil {
		return fmt.Errorf("anomaly_alerts 唯一索引创建失败: %w", err)
	}
	logger.Info("anomaly_alerts 唯一索引已创建，ML 异常落库启用 upsert 去重")
	return nil
}

// migrateBehaviorAlertDedup 为 behavior_alerts 建 (tenant_id, host_id, metric) 唯一索引，
// 使 BDE 落库改 upsert：同主机同指标的稳态偏离每 60s 复发只累加 hit_count，不再无限新增行。
//
// 历史问题：BDE 逐条 db.Create，无去重键 → 同一稳态偏离每快照一行，实测积压 ~197 万全 open。
// 建唯一索引前须先合并存量重复行（否则唯一索引创建失败）。
// 幂等：索引已存在则直接返回。
func migrateBehaviorAlertDedup(db *gorm.DB, logger *zap.Logger) error {
	if db.Migrator().HasIndex(&model.BehaviorAlert{}, behaviorAlertDedupIndex) {
		return nil
	}

	// 存量去重仅在 MySQL 上执行（sqlite 测试环境无存量数据）。
	// 保留每组最小 id 行，其 hit_count 置为该组行数，删除其余重复行。
	if db.Dialector.Name() == "mysql" {
		if err := db.Exec(`
UPDATE behavior_alerts b
JOIN (
	SELECT MIN(id) AS keep_id, COUNT(*) AS cnt
	FROM behavior_alerts
	GROUP BY tenant_id, host_id, metric
) g ON b.id = g.keep_id
SET b.hit_count = g.cnt`).Error; err != nil {
			return fmt.Errorf("behavior_alerts 累加 hit_count 失败: %w", err)
		}
		r := db.Exec(`
DELETE b FROM behavior_alerts b
JOIN (
	SELECT MIN(id) AS keep_id, tenant_id, host_id, metric
	FROM behavior_alerts
	GROUP BY tenant_id, host_id, metric
) g ON b.tenant_id = g.tenant_id AND b.host_id = g.host_id AND b.metric = g.metric
WHERE b.id <> g.keep_id`)
		if r.Error != nil {
			return fmt.Errorf("behavior_alerts 删除重复行失败: %w", r.Error)
		}
		if r.RowsAffected > 0 {
			logger.Info("behavior_alerts 存量去重", zap.Int64("removed", r.RowsAffected))
		}
	}

	if err := db.Exec("CREATE UNIQUE INDEX " + behaviorAlertDedupIndex +
		" ON behavior_alerts (tenant_id, host_id, metric)").Error; err != nil {
		return fmt.Errorf("behavior_alerts 唯一索引创建失败: %w", err)
	}
	logger.Info("behavior_alerts 唯一索引已创建，BDE 落库启用 upsert 去重")
	return nil
}

// migrateCleanupLegacyHostVuln 启动时清 OSS-Fuzz 垃圾 + 通用 host_vuln FP。
//
// 主要 host_vuln FP 清理逻辑下沉到 advisory.CleanupHostVulnFP（同时被 Coordinator.Sync 末尾调用），
// 这里仅处理 OSS-Fuzz vulnerabilities 表层垃圾（同样导致 host_vuln 误报），
// 然后委托 advisory 包做 host_vuln 清理。
//
// 幂等：基于 SQL 条件删除，多次运行无副作用。
func migrateCleanupLegacyHostVuln(db *gorm.DB, logger *zap.Logger) error {
	// OSS-Fuzz crash ID（OSV-YYYY-NNN）当 CVE 入库的 vulnerabilities + 级联 host_vulnerabilities
	// 上游 osv.dev 把 OSS-Fuzz crash 记录与 CVE 同 namespace，旧 extractCVEs fallback 误把
	// OSV-YYYY-NNN 写到 cve_id 字段，这类记录构成误报的主要来源。
	var ossFuzzIDs []uint
	if err := db.Table("vulnerabilities").
		Where("cve_id REGEXP '^OSV-[0-9]{4}-[0-9]+$'").
		Pluck("id", &ossFuzzIDs).Error; err != nil {
		return fmt.Errorf("查询 OSS-Fuzz vuln id 失败: %w", err)
	}
	if len(ossFuzzIDs) > 0 {
		r1 := db.Exec("DELETE FROM host_vulnerabilities WHERE vuln_id IN ?", ossFuzzIDs)
		r2 := db.Exec("DELETE FROM vulnerabilities WHERE id IN ?", ossFuzzIDs)
		logger.Info("清理 OSS-Fuzz 垃圾",
			zap.Int64("host_vuln_deleted", r1.RowsAffected),
			zap.Int64("vuln_deleted", r2.RowsAffected))
	}

	// NVD description 含 OS/arch qualifier 限定的 host_vuln（仅 migration 跑，
	// 因 description 字段不在 sync 路径上动）
	nvdQualifierRegex := `(on 32-bit|32-bit builds?|microsoft windows|windows-only|freebsd only|macos only|macos x|iphone|ios only|android only)`
	r7 := db.Exec(`
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON hv.vuln_id = v.id
JOIN hosts h ON h.host_id = hv.host_id
WHERE v.source = 'nvd'
  AND LOWER(h.os_family) IN ('rhel','rocky','centos','centos-stream','almalinux','oraclelinux','ubuntu','debian','alpine','sles','opensuse')
  AND LOWER(v.description) REGEXP ?`, nvdQualifierRegex)
	if r7.Error == nil && r7.RowsAffected > 0 {
		logger.Info("NVD OS/arch qualifier host_vuln 已清理",
			zap.Int64("deleted", r7.RowsAffected))
	}

	// 委托 advisory 包做通用 host_vuln FP 清理(同一份逻辑被 Coordinator.Sync 复用)
	advisory.CleanupHostVulnFP(db, logger)
	advisory.CleanupAlreadyPatched(db, logger)
	return nil
}

// migrateCategorizeExistingVulns 给历史 vulnerabilities 回填 vuln_category + restart_action
// 分批 1000 行 UPDATE，每批 sleep 50ms 避免长事务锁表。
// 幂等：只处理 vuln_category='other' AND restart_action='unknown' 的（默认值）
func migrateCategorizeExistingVulns(db *gorm.DB, logger *zap.Logger) error {
	const batchSize = 1000
	var total int64
	db.Model(&model.Vulnerability{}).
		Where("(vuln_category = ? OR vuln_category = '' OR vuln_category IS NULL)", model.VulnCategoryOther).
		Count(&total)
	if total == 0 {
		return nil
	}
	logger.Info("开始回填 vuln 分类", zap.Int64("total", total))

	scanned := 0
	changed := 0
	changedStats := map[string]int{}
	// 按 id 分页避免死循环：cat 仍返回 'other' 时行不会从过滤集移出，
	// 不加 id > lastID 会被反复 fetch 同一批
	var lastID uint = 0
	for {
		var batch []model.Vulnerability
		if err := db.Select("id, component, purl").
			Where("(vuln_category = ? OR vuln_category = '' OR vuln_category IS NULL) AND id > ?",
				model.VulnCategoryOther, lastID).
			Order("id ASC").
			Limit(batchSize).
			Find(&batch).Error; err != nil {
			return fmt.Errorf("拉批次失败: %w", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, v := range batch {
			scanned++
			lastID = v.ID
			cat, act := model.CategorizeVuln(v.Component, v.PURL)
			// 规则未命中（仍 other）→ 不写 DB，下次 migration 同样跳过避免无效 IO
			if cat == model.VulnCategoryOther {
				continue
			}
			if err := db.Model(&model.Vulnerability{}).
				Where("id = ?", v.ID).
				UpdateColumns(map[string]any{
					"vuln_category":  cat,
					"restart_action": act,
				}).Error; err != nil {
				logger.Warn("vuln 分类回填失败",
					zap.Uint("id", v.ID), zap.Error(err))
				continue
			}
			changedStats[cat]++
			changed++
		}
		logger.Info("vuln 分类回填进度",
			zap.Int("scanned", scanned), zap.Int("changed", changed), zap.Int64("total", total))
		time.Sleep(50 * time.Millisecond)
		if len(batch) < batchSize {
			break
		}
	}

	// 完成后查整库分布给运维一个全局视角（不只是本次 changed 的那部分）
	type catRow struct {
		Category string `gorm:"column:vuln_category"`
		N        int64  `gorm:"column:n"`
	}
	var overall []catRow
	db.Model(&model.Vulnerability{}).
		Select("vuln_category, COUNT(*) as n").
		Group("vuln_category").
		Scan(&overall)
	overallStats := map[string]int64{}
	for _, r := range overall {
		overallStats[r.Category] = r.N
	}

	logger.Info("vuln 分类回填完成",
		zap.Int("scanned", scanned),
		zap.Int("changed", changed),
		zap.Any("changed_by_category", changedStats),
		zap.Any("overall_distribution", overallStats))
	return nil
}

// migrateAlertSource 为存量告警记录回填 source 字段
func migrateAlertSource(db *gorm.DB, logger *zap.Logger) error {
	// 检查是否有需要回填的记录
	var count int64
	db.Model(&model.Alert{}).Where("source IS NULL OR source = ''").Count(&count)
	if count == 0 {
		return nil
	}

	logger.Info("开始回填告警 source 字段", zap.Int64("count", count))

	// 1. Agent 离线告警
	r := db.Model(&model.Alert{}).
		Where("(source IS NULL OR source = '') AND category = ?", "agent_offline").
		Update("source", model.AlertSourceAgent)
	if r.RowsAffected > 0 {
		logger.Info("回填 agent 来源", zap.Int64("count", r.RowsAffected))
	}

	// 2. 检测告警（CEL 规则 + 端口扫描）
	r = db.Model(&model.Alert{}).
		Where("(source IS NULL OR source = '') AND (rule_id LIKE ? OR rule_id = ?)", "cel-%", "scan-detector").
		Update("source", model.AlertSourceDetection)
	if r.RowsAffected > 0 {
		logger.Info("回填 detection 来源", zap.Int64("count", r.RowsAffected))
	}

	// 3. 其余未标记的 → 基线告警
	r = db.Model(&model.Alert{}).
		Where("source IS NULL OR source = ''").
		Update("source", model.AlertSourceBaseline)
	if r.RowsAffected > 0 {
		logger.Info("回填 baseline 来源", zap.Int64("count", r.RowsAffected))
	}

	return nil
}

// migrateSensorToEDR 将数据库中残留的 sensor/runtime 相关数据迁移为 edr
// 注意：此迁移仅处理历史数据重命名，edr 插件本身已在 migrateRemoveEDRPlugin 中清理
func migrateSensorToEDR(db *gorm.DB, logger *zap.Logger) error {
	// 1. alerts 表：source='runtime' → 'edr'
	r := db.Table("alerts").Where("source = ?", "runtime").Update("source", "edr")
	if r.RowsAffected > 0 {
		logger.Info("alerts: source runtime → edr", zap.Int64("count", r.RowsAffected))
	}

	// 2. notifications 表：notify_category='runtime_alert' → 'edr_alert'
	r = db.Table("notifications").Where("notify_category = ?", "runtime_alert").Update("notify_category", "edr_alert")
	if r.RowsAffected > 0 {
		logger.Info("notifications: runtime_alert → edr_alert", zap.Int64("count", r.RowsAffected))
	}

	// 3. generated_reports 表：report_type='runtime' → 'edr'
	r = db.Table("generated_reports").Where("report_type = ?", "runtime").Update("report_type", "edr")
	if r.RowsAffected > 0 {
		logger.Info("generated_reports: runtime → edr", zap.Int64("count", r.RowsAffected))
	}

	return nil
}

// migrateMarkFakeVulns 标记历史 description-keyword-match 误产物为 confidence='low'，
// 不再 soft delete（之前过激删除真 Linux kernel CVE，因 NVD awaiting analysis 也无 CPE）。
//
// 真假区分需重新 import：advisory package coordinator 走 CPE/PURL/Advisory 严格匹配，
// 历史 source=nvd 数据视为 low confidence，UI 按 confidence 过滤显示，不破坏数据。
// 幂等：已标记 confidence 的不重复。
func migrateMarkFakeVulns(db *gorm.DB, logger *zap.Logger) error {
	r := db.Table("vulnerabilities").
		Where("source = ? AND (confidence IS NULL OR confidence = '')", "nvd").
		Update("confidence", model.VulnConfidenceLow)
	if r.Error != nil {
		return fmt.Errorf("标记历史 nvd vuln confidence 失败: %w", r.Error)
	}
	if r.RowsAffected > 0 {
		logger.Info("历史 nvd vuln 标记为 confidence=low（仅标记，不删除）",
			zap.Int64("count", r.RowsAffected))
	}
	// 历史 source=osv 也标 low（实际看到是 RHEL erratum 混入，confidence 不准）
	r2 := db.Table("vulnerabilities").
		Where("source = ? AND (confidence IS NULL OR confidence = '')", "osv").
		Update("confidence", model.VulnConfidenceLow)
	if r2.RowsAffected > 0 {
		logger.Info("历史 osv vuln 标记为 confidence=low",
			zap.Int64("count", r2.RowsAffected))
	}
	// redhat 同理（OS major filter 缺失）
	r3 := db.Table("vulnerabilities").
		Where("source = ? AND (confidence IS NULL OR confidence = '')", "redhat").
		Update("confidence", model.VulnConfidenceLow)
	if r3.RowsAffected > 0 {
		logger.Info("历史 redhat vuln 标记为 confidence=low",
			zap.Int64("count", r3.RowsAffected))
	}
	return nil
}

// migrateRestoreErroneouslyDeletedVulns 回滚之前 migrateMarkFakeVulns 误 soft delete
// 真 Linux kernel CVE 的副作用。
// 仅在 dev/prod 已经执行过老 migrateMarkFakeVulns 时需要。幂等。
func migrateRestoreErroneouslyDeletedVulns(db *gorm.DB, logger *zap.Logger) error {
	r := db.Table("vulnerabilities").
		Where("confidence = ? AND deleted_at IS NOT NULL", model.VulnConfidenceFake).
		Updates(map[string]any{
			"confidence": model.VulnConfidenceLow,
			"deleted_at": nil,
		})
	if r.Error != nil {
		return fmt.Errorf("回滚误删 vuln 失败: %w", r.Error)
	}
	if r.RowsAffected > 0 {
		// 同步回滚关联 host_vulnerabilities（按 vuln_id 反查）
		var vulnIDs []uint
		db.Table("vulnerabilities").
			Where("confidence = ?", model.VulnConfidenceLow).
			Pluck("id", &vulnIDs)
		if len(vulnIDs) > 0 {
			db.Table("host_vulnerabilities").
				Where("vuln_id IN ? AND deleted_at IS NOT NULL", vulnIDs).
				Update("deleted_at", nil)
		}
		logger.Info("回滚之前误 soft delete 的 vuln（标 confidence=low）",
			zap.Int64("restored", r.RowsAffected))
	}
	return nil
}

// migrateRemoveEDRPlugin 清理废弃的 edr 插件和 tetragon 依赖
// EDR 检测功能已内置到 Agent 二进制 (v1.2.0+)，不再需要独立的 edr 插件和 tetragon 运行时
// 此迁移幂等：已清理的环境不会重复执行
func migrateRemoveEDRPlugin(db *gorm.DB, logger *zap.Logger) error {
	// 1. 清理 plugin_configs 中的 edr 和 sensor 插件配置
	// sensor 是 edr 的旧名称，一并清理
	r := db.Table("plugin_configs").
		Where("name IN (?, ?) AND deleted_at IS NULL", "edr", "sensor").
		Update("deleted_at", time.Now())
	if r.RowsAffected > 0 {
		logger.Info("已清理 edr/sensor 插件配置", zap.Int64("count", r.RowsAffected))
	}

	// 2. 软删除 edr、tetragon、tetrgon(历史 typo) 组件及其版本和包
	obsoleteNames := []string{"edr", "sensor", "tetragon", "tetrgon"}

	// 查找需要清理的组件 ID
	var componentIDs []uint
	db.Table("components").
		Where("name IN ? AND deleted_at IS NULL", obsoleteNames).
		Pluck("id", &componentIDs)

	if len(componentIDs) == 0 {
		return nil // 已清理
	}

	// 软删除关联的包记录
	var versionIDs []uint
	db.Table("component_versions").
		Where("component_id IN ?", componentIDs).
		Pluck("id", &versionIDs)

	if len(versionIDs) > 0 {
		r = db.Table("component_packages").
			Where("version_id IN ? AND deleted_at IS NULL", versionIDs).
			Update("deleted_at", time.Now())
		if r.RowsAffected > 0 {
			logger.Info("已清理废弃组件包", zap.Int64("count", r.RowsAffected))
		}

		// 软删除版本记录
		r = db.Table("component_versions").
			Where("id IN ? AND deleted_at IS NULL", versionIDs).
			Update("deleted_at", time.Now())
		if r.RowsAffected > 0 {
			logger.Info("已清理废弃组件版本", zap.Int64("count", r.RowsAffected))
		}
	}

	// 软删除组件记录
	r = db.Table("components").
		Where("id IN ? AND deleted_at IS NULL", componentIDs).
		Update("deleted_at", time.Now())
	if r.RowsAffected > 0 {
		logger.Info("已清理废弃组件",
			zap.Int64("count", r.RowsAffected),
			zap.Strings("names", obsoleteNames))
	}

	return nil
}

// migrateNotificationCategory 为现有通知配置设置 notify_category
func migrateNotificationCategory(db *gorm.DB, logger *zap.Logger) error {
	// 1. 将名称包含 "离线" 的通知设置为 agent_offline
	result := db.Model(&model.Notification{}).
		Where("(notify_category IS NULL OR notify_category = '')").
		Where("name LIKE ?", "%离线%").
		Update("notify_category", model.NotifyCategoryAgentOffline)
	if result.Error != nil {
		logger.Warn("更新 Agent 离线通知类别失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新 Agent 离线通知类别",
			zap.Int64("count", result.RowsAffected))
	}

	// 2. 将其他通知设置为 baseline_alert（默认）
	result = db.Model(&model.Notification{}).
		Where("notify_category IS NULL OR notify_category = ''").
		Update("notify_category", model.NotifyCategoryBaselineAlert)
	if result.Error != nil {
		logger.Warn("更新基线告警通知类别失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新基线告警通知类别",
			zap.Int64("count", result.RowsAffected))
	}

	// 3. 清空 Agent 离线通知的 severities（不需要等级配置）
	result = db.Model(&model.Notification{}).
		Where("notify_category = ?", model.NotifyCategoryAgentOffline).
		Update("severities", model.StringArray{})
	if result.Error != nil {
		logger.Warn("清空 Agent 离线通知的 severities 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已清空 Agent 离线通知的 severities",
			zap.Int64("count", result.RowsAffected))
	}

	return nil
}

// migrateRuntimeTypes 为现有数据设置默认的运行时类型
func migrateRuntimeTypes(db *gorm.DB, logger *zap.Logger) error {
	// 1. 更新现有主机的 runtime_type
	// 如果 is_container = true，设置为 docker；否则设置为 vm
	result := db.Model(&model.Host{}).
		Where("runtime_type IS NULL OR runtime_type = ''").
		Where("is_container = ?", true).
		Update("runtime_type", model.RuntimeTypeDocker)
	if result.Error != nil {
		logger.Warn("更新容器主机的 runtime_type 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新容器主机的 runtime_type",
			zap.Int64("count", result.RowsAffected),
			zap.String("runtime_type", string(model.RuntimeTypeDocker)))
	}

	result = db.Model(&model.Host{}).
		Where("runtime_type IS NULL OR runtime_type = ''").
		Where("is_container = ? OR is_container IS NULL", false).
		Update("runtime_type", model.RuntimeTypeVM)
	if result.Error != nil {
		logger.Warn("更新虚拟机主机的 runtime_type 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新虚拟机主机的 runtime_type",
			zap.Int64("count", result.RowsAffected),
			zap.String("runtime_type", string(model.RuntimeTypeVM)))
	}

	// 2. 更新所有策略的 runtime_types 为 ["vm"]
	// 这里强制更新所有策略，确保所有策略都有默认的运行时类型
	result = db.Model(&model.Policy{}).
		Where("runtime_types IS NULL OR runtime_types = '[]' OR runtime_types = '' OR runtime_types = 'null'").
		Update("runtime_types", model.StringArray{"vm"})
	if result.Error != nil {
		logger.Warn("更新策略的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新策略的 runtime_types",
			zap.Int64("count", result.RowsAffected),
			zap.Strings("runtime_types", []string{"vm"}))
	}

	// 2.1 额外检查：强制更新那些 runtime_types 可能包含无效值的记录
	// 使用 JSON 包含检查，如果不包含有效值则更新
	result = db.Exec(`
		UPDATE policies 
		SET runtime_types = '["vm"]' 
		WHERE runtime_types NOT LIKE '%"vm"%' 
		  AND runtime_types NOT LIKE '%"docker"%' 
		  AND runtime_types NOT LIKE '%"k8s"%'
	`)
	if result.Error != nil {
		logger.Warn("强制更新策略的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("强制更新了无效的策略 runtime_types",
			zap.Int64("count", result.RowsAffected))
	}

	// 3. 清空现有规则的 runtime_types，让它们继承策略的设置
	// 规则默认继承策略的 RuntimeTypes，不需要单独设置
	result = db.Model(&model.Rule{}).
		Where("runtime_types IS NOT NULL AND runtime_types != '[]' AND runtime_types != ''").
		Update("runtime_types", model.StringArray{})
	if result.Error != nil {
		logger.Warn("清空规则的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已清空规则的 runtime_types（规则将继承策略的设置）",
			zap.Int64("count", result.RowsAffected))
	}

	// 4. 更新插件配置的 runtime_types
	// baseline 和 fim 仅适用于 VM
	result = db.Model(&model.PluginConfig{}).
		Where("name IN (?, ?)", "baseline", "fim").
		Where("runtime_types IS NULL OR runtime_types = '[]' OR runtime_types = '' OR runtime_types = 'null'").
		Update("runtime_types", model.StringArray{"vm"})
	if result.Error != nil {
		logger.Warn("更新 baseline/fim 插件的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新 baseline/fim 插件的 runtime_types",
			zap.Int64("count", result.RowsAffected),
			zap.Strings("runtime_types", []string{"vm"}))
	}

	// collector 适用于全平台
	result = db.Model(&model.PluginConfig{}).
		Where("name = ?", "collector").
		Where("runtime_types IS NULL OR runtime_types = '[]' OR runtime_types = '' OR runtime_types = 'null'").
		Update("runtime_types", model.StringArray{"vm", "docker", "k8s"})
	if result.Error != nil {
		logger.Warn("更新 collector 插件的 runtime_types 失败", zap.Error(result.Error))
	} else if result.RowsAffected > 0 {
		logger.Info("已更新 collector 插件的 runtime_types",
			zap.Int64("count", result.RowsAffected),
			zap.Strings("runtime_types", []string{"vm", "docker", "k8s"}))
	}

	return nil
}

// migrateAssetTableIDColumns 扩展资产表的 ID 列从 varchar(64) 到 varchar(128)
// GORM AutoMigrate 不保证会扩展已有列的长度，需要显式 ALTER TABLE
func migrateAssetTableIDColumns(db *gorm.DB, logger *zap.Logger) error {
	// 所有需要扩展 id 列的资产表（ID 格式为 "{host_id}-{xxx}"，host_id 是 64 字符 SHA256）
	tables := []string{
		"processes", "ports", "asset_users", "software",
		"containers", "apps", "net_interfaces", "volumes",
		"kmods", "services", "crons",
	}

	for _, table := range tables {
		// 先检查表是否存在
		var exists bool
		if err := db.Raw(
			"SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
			table,
		).Scan(&exists).Error; err != nil {
			logger.Warn("检查表是否存在失败", zap.String("table", table), zap.Error(err))
			continue
		}
		if !exists {
			continue
		}

		// 检查当前列长度
		var columnType string
		if err := db.Raw(
			"SELECT COLUMN_TYPE FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = 'id'",
			table,
		).Scan(&columnType).Error; err != nil {
			logger.Warn("查询列类型失败", zap.String("table", table), zap.Error(err))
			continue
		}

		// 如果已经是 varchar(128) 或更大则跳过
		if columnType == "varchar(128)" {
			continue
		}

		// 执行 ALTER TABLE
		sql := fmt.Sprintf("ALTER TABLE `%s` MODIFY COLUMN `id` varchar(128) NOT NULL", table)
		if err := db.Exec(sql).Error; err != nil {
			logger.Error("扩展资产表ID列失败", zap.String("table", table), zap.String("old_type", columnType), zap.Error(err))
		} else {
			logger.Info("扩展资产表ID列成功", zap.String("table", table), zap.String("old_type", columnType), zap.String("new_type", "varchar(128)"))
		}
	}

	return nil
}

// migrateAlertResultIDColumn 扩展 alerts 表的 result_id 列从 varchar(64) 到 varchar(128)
// 离线告警 ID 格式为 "offline-{64位hash}"，总长度 72 字符，超过 varchar(64)
func migrateAlertResultIDColumn(db *gorm.DB, logger *zap.Logger) error {
	// 检查表是否存在
	var exists bool
	if err := db.Raw(
		"SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'alerts'",
	).Scan(&exists).Error; err != nil {
		return err
	}
	if !exists {
		return nil
	}

	// 检查当前列长度
	var columnType string
	if err := db.Raw(
		"SELECT COLUMN_TYPE FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'alerts' AND column_name = 'result_id'",
	).Scan(&columnType).Error; err != nil {
		return err
	}

	// 如果已经是 varchar(128) 或更大则跳过
	if columnType == "varchar(128)" {
		return nil
	}

	// 执行 ALTER TABLE
	if err := db.Exec("ALTER TABLE `alerts` MODIFY COLUMN `result_id` varchar(128) NOT NULL").Error; err != nil {
		logger.Error("扩展告警表result_id列失败", zap.String("old_type", columnType), zap.Error(err))
		return err
	}
	logger.Info("扩展告警表result_id列成功", zap.String("old_type", columnType), zap.String("new_type", "varchar(128)"))

	return nil
}

// migrateIncidentIDColumn 扩展 incidents 表的 incident_id 列从 varchar(64) 到 varchar(128)
// incident_id 格式为 "inc-{64位host_id}-{unix秒}"，总长 79 字符，超过 varchar(64) 导致插入报
// Error 1406 (Data too long)，攻击链关联事件无法落库。
func migrateIncidentIDColumn(db *gorm.DB, logger *zap.Logger) error {
	// 检查表是否存在
	var exists bool
	if err := db.Raw(
		"SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'incidents'",
	).Scan(&exists).Error; err != nil {
		return err
	}
	if !exists {
		return nil
	}

	// 检查当前列长度
	var columnType string
	if err := db.Raw(
		"SELECT COLUMN_TYPE FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'incidents' AND column_name = 'incident_id'",
	).Scan(&columnType).Error; err != nil {
		return err
	}

	// 如果已经是 varchar(128) 或更大则跳过
	if columnType == "varchar(128)" {
		return nil
	}

	// 执行 ALTER TABLE
	if err := db.Exec("ALTER TABLE `incidents` MODIFY COLUMN `incident_id` varchar(128) NOT NULL").Error; err != nil {
		logger.Error("扩展事件表incident_id列失败", zap.String("old_type", columnType), zap.Error(err))
		return err
	}
	logger.Info("扩展事件表incident_id列成功", zap.String("old_type", columnType), zap.String("new_type", "varchar(128)"))

	return nil
}

// migrateScanResultsCompositeKey 将 scan_results 和 fix_results 表从单列主键(result_id)
// 迁移为复合主键(task_id, host_id, rule_id)。
//
// 每一步独立 idempotent 检查（DROP PRIMARY / ADD PRIMARY / DROP COLUMN 任意一步
// 之前部分成功也能安全续跑），避免历史"半完成"状态报 1091 / 1068 错误。
func migrateScanResultsCompositeKey(db *gorm.DB, logger *zap.Logger) error {
	for _, table := range []string{"scan_results", "fix_results"} {
		var hasResultID bool
		if err := db.Raw(
			"SELECT COUNT(*) > 0 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = 'result_id'",
			table,
		).Scan(&hasResultID).Error; err != nil {
			return err
		}
		if !hasResultID {
			continue // 完全已迁移，跳过
		}

		logger.Info("开始迁移主键：result_id → (task_id, host_id, rule_id)", zap.String("table", table))

		// Step 1: 当前 PRIMARY 是单列 result_id 时才 DROP
		// （之前部分完成的迁移可能已 DROP，再 DROP 会报 1091）
		var pkColumns int
		if err := db.Raw(
			"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = 'PRIMARY'",
			table,
		).Scan(&pkColumns).Error; err != nil {
			return err
		}
		if pkColumns > 0 {
			if err := db.Exec(fmt.Sprintf("ALTER TABLE `%s` DROP PRIMARY KEY", table)).Error; err != nil {
				logger.Error("DROP PRIMARY KEY 失败", zap.String("table", table), zap.Error(err))
				return err
			}
		} else {
			logger.Info("PRIMARY KEY 已不存在，跳过 DROP", zap.String("table", table))
		}

		// Step 1.5: 去重 — 历史数据可能存在 (task_id, host_id, rule_id) 重复行
		// （fix_results 业务侧 INSERT 而非 UPSERT，任务重试时会插入重复）。
		// 保留每组 result_id 字典序最大的一行（视为最新），删其他。
		dedupSQL := fmt.Sprintf(
			"DELETE t1 FROM `%s` t1 INNER JOIN `%s` t2 "+
				"ON t1.task_id = t2.task_id AND t1.host_id = t2.host_id "+
				"AND t1.rule_id = t2.rule_id AND t1.result_id < t2.result_id",
			table, table)
		dedupResult := db.Exec(dedupSQL)
		if dedupResult.Error != nil {
			logger.Error("去重失败", zap.String("table", table), zap.Error(dedupResult.Error))
			return dedupResult.Error
		}
		if dedupResult.RowsAffected > 0 {
			logger.Info("迁移前去重完成", zap.String("table", table), zap.Int64("deleted", dedupResult.RowsAffected))
		}

		// Step 2: 新复合主键 (task_id, host_id, rule_id) 不存在时才 ADD
		var newPKColumns int
		if err := db.Raw(`
			SELECT COUNT(*) FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = ?
			  AND index_name = 'PRIMARY'
			  AND column_name IN ('task_id', 'host_id', 'rule_id')
		`, table).Scan(&newPKColumns).Error; err != nil {
			return err
		}
		if newPKColumns < 3 {
			if err := db.Exec(fmt.Sprintf("ALTER TABLE `%s` ADD PRIMARY KEY (`task_id`, `host_id`, `rule_id`)", table)).Error; err != nil {
				logger.Error("ADD PRIMARY KEY 失败", zap.String("table", table), zap.Error(err))
				return err
			}
		} else {
			logger.Info("复合主键已存在，跳过 ADD", zap.String("table", table))
		}

		// Step 3: 删除旧 result_id 列
		if err := db.Exec(fmt.Sprintf("ALTER TABLE `%s` DROP COLUMN `result_id`", table)).Error; err != nil {
			logger.Error("DROP COLUMN result_id 失败", zap.String("table", table), zap.Error(err))
			return err
		}

		logger.Info("主键迁移完成", zap.String("table", table))
	}

	return nil
}

// migratePolicyGroupName 更新策略组名称为"主机系统基线组"
func migratePolicyGroupName(db *gorm.DB, logger *zap.Logger) error {
	// 更新默认策略组的名称（从"系统基线组"改为"主机系统基线组"）
	result := db.Model(&model.PolicyGroup{}).
		Where("id = ?", "system-baseline").
		Where("name = ?", "系统基线组").
		Updates(map[string]any{
			"name":        "主机系统基线组",
			"description": "系统内置的基线检查策略组，包含 Linux 主机操作系统安全基线检查策略（仅适用于主机/虚拟机，不适用于容器）",
			"icon":        "🖥",
		})
	if result.Error != nil {
		logger.Warn("更新策略组名称失败", zap.Error(result.Error))
		return result.Error
	}
	if result.RowsAffected > 0 {
		logger.Info("已更新策略组名称",
			zap.String("old_name", "系统基线组"),
			zap.String("new_name", "主机系统基线组"))
	}

	return nil
}

// migrateBaselineBuiltinFlag 一次性回填：将历史内置基线策略/规则标记为 builtin=true。
// builtin 字段是本版本新增，AutoMigrate 给存量行默认 false。system-baseline 组下的策略/规则
// 全部来自文件同步，属内置，必须回填——否则启动同步会把它们误判为用户自定义而跳过。
// 用 system_config 一次性标记保证只跑一次，绝不影响日后用户导入到该组的自定义规则。
func migrateBaselineBuiltinFlag(db *gorm.DB, logger *zap.Logger) error {
	const flagKey = "baseline_builtin_backfilled"

	var cfg model.SystemConfig
	err := db.Where("`key` = ? AND category = ?", flagKey, "system").First(&cfg).Error
	if err == nil {
		return nil // 已回填过
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}

	// 取 system-baseline 组下所有策略 ID
	var builtinPolicyIDs []string
	if err := db.Model(&model.Policy{}).
		Where("group_id = ?", DefaultPolicyGroupID).
		Pluck("id", &builtinPolicyIDs).Error; err != nil {
		return err
	}

	var policiesAffected, rulesAffected int64
	if len(builtinPolicyIDs) > 0 {
		pRes := db.Model(&model.Policy{}).
			Where("group_id = ? AND builtin = ?", DefaultPolicyGroupID, false).
			Update("builtin", true)
		if pRes.Error != nil {
			return pRes.Error
		}
		policiesAffected = pRes.RowsAffected

		rRes := db.Model(&model.Rule{}).
			Where("policy_id IN ? AND builtin = ?", builtinPolicyIDs, false).
			Update("builtin", true)
		if rRes.Error != nil {
			return rRes.Error
		}
		rulesAffected = rRes.RowsAffected
	}

	// 标记已回填（即使 0 行也标记，保证新装 DB 不重复跑）
	if err := db.Create(&model.SystemConfig{
		Key:         flagKey,
		Value:       "true",
		Category:    "system",
		Description: "基线 builtin 字段一次性回填完成",
	}).Error; err != nil {
		return err
	}

	logger.Info("基线 builtin 回填完成",
		zap.Int64("policies", policiesAffected),
		zap.Int64("rules", rulesAffected))
	return nil
}

// migrateComponentTables 处理组件相关表的迁移
// 由于数据模型从扁平结构改为层级结构（Component → Version → Package），
// 旧的 component_packages 表可能有数据但没有有效的 version_id 外键
func migrateComponentTables(db *gorm.DB, logger *zap.Logger) error {
	// 检查 component_packages 表是否存在
	var packagesExists bool
	if err := db.Raw("SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'component_packages'").Scan(&packagesExists).Error; err != nil {
		return err
	}

	if !packagesExists {
		return nil // 表不存在，无需处理
	}

	// 检查 component_versions 表是否存在
	var versionsExists bool
	if err := db.Raw("SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'component_versions'").Scan(&versionsExists).Error; err != nil {
		return err
	}

	// 如果 component_packages 存在但 component_versions 不存在，说明是旧结构
	// 需要清理旧数据，让迁移重新创建表
	if !versionsExists {
		logger.Info("检测到旧的组件包表结构，清理旧数据以便迁移")

		// 删除旧表（按依赖顺序）
		tables := []string{"component_packages", "component_versions", "components"}
		for _, table := range tables {
			if err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)).Error; err != nil {
				logger.Warn("删除旧组件表失败", zap.String("table", table), zap.Error(err))
			} else {
				logger.Info("删除旧组件表成功", zap.String("table", table))
			}
		}
		return nil
	}

	// 检查 component_packages 中是否有孤立数据（version_id 不在 component_versions 中）
	var orphanCount int64
	if err := db.Raw(`
		SELECT COUNT(*) FROM component_packages cp
		LEFT JOIN component_versions cv ON cp.version_id = cv.id
		WHERE cv.id IS NULL AND cp.version_id IS NOT NULL
	`).Scan(&orphanCount).Error; err != nil {
		// 查询失败可能是因为表结构不同，尝试清理
		logger.Warn("检查孤立数据失败，尝试清理组件表", zap.Error(err))
		cleanupComponentTables(db, logger)
		return nil
	}

	if orphanCount > 0 {
		logger.Info("检测到孤立的组件包数据，清理旧数据", zap.Int64("orphan_count", orphanCount))
		cleanupComponentTables(db, logger)
	}

	return nil
}

// cleanupComponentTables 清理组件相关表
func cleanupComponentTables(db *gorm.DB, logger *zap.Logger) {
	// 先删除外键约束
	db.Exec("SET FOREIGN_KEY_CHECKS = 0")
	defer db.Exec("SET FOREIGN_KEY_CHECKS = 1")

	tables := []string{"component_packages", "component_versions", "components"}
	for _, table := range tables {
		if err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)).Error; err != nil {
			logger.Warn("删除组件表失败", zap.String("table", table), zap.Error(err))
		} else {
			logger.Info("删除组件表成功", zap.String("table", table))
		}
	}
}

// Rollback 回滚数据库（谨慎使用）
func Rollback(db *gorm.DB, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Warn("开始数据库回滚（删除所有表）")

	// 先禁用外键检查
	db.Exec("SET FOREIGN_KEY_CHECKS = 0")
	defer db.Exec("SET FOREIGN_KEY_CHECKS = 1")

	// 删除所有表（按依赖顺序）
	tables := []string{
		// 组件相关表
		"component_packages",
		"component_versions",
		"components",
		// 插件配置
		"plugin_configs",
		// 检测和任务
		"scan_results",
		"scan_tasks",
		"rules",
		"policies",
		"policy_groups",
		// 资产表
		"processes",
		"ports",
		"asset_users",
		"software",
		"containers",
		"apps",
		"net_interfaces",
		"volumes",
		"kmods",
		"services",
		"crons",
		// 监控数据
		"host_metrics",
		"host_metrics_hourly",
		// 系统配置
		"alerts",
		"notifications",
		"system_configs",
		"business_lines",
		// 核心表
		"hosts",
		"users",
	}

	for _, table := range tables {
		if err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", table)).Error; err != nil {
			logger.Error("删除表失败", zap.Error(err), zap.String("table", table))
			return fmt.Errorf("删除表 %s 失败: %w", table, err)
		}
		logger.Info("删除表成功", zap.String("table", table))
	}

	logger.Info("数据库回滚完成")
	return nil
}
