// Package migration 提供数据库初始化数据功能
package migration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	builtinrules "github.com/matrixplusio/mxcwpp/configs/rules"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/plugins/baseline/engine"
)

// DefaultPolicyGroupID 默认策略组ID
const DefaultPolicyGroupID = "system-baseline"

type managedPluginBootstrap struct {
	Name         string
	Type         model.PluginType
	RuntimeTypes model.StringArray
	Description  string
	Detail       string
}

// InitDefaultData 初始化默认数据（策略和规则）
// 首次启动时创建默认策略组和策略数据，后续启动不再重建用户已删除的数据
func InitDefaultData(db *gorm.DB, logger *zap.Logger, policyDir string, pluginsCfg *config.PluginsConfig) error {
	if logger == nil {
		logger = zap.NewNop()
	}

	logger.Info("开始初始化默认数据", zap.String("policy_dir", policyDir))

	// v2.0: 初始化默认租户 t-default。所有 v1.x 升级的数据归属于该租户。
	// 必须先于 initDefaultUsers，admin 用户依赖默认租户存在。
	if err := initDefaultTenant(db, logger); err != nil {
		return fmt.Errorf("初始化默认租户失败: %w", err)
	}

	// 初始化默认用户（始终执行，确保admin用户存在）
	if err := initDefaultUsers(db, logger); err != nil {
		return fmt.Errorf("初始化默认用户失败: %w", err)
	}

	// 初始化 RBAC 权限元数据（始终执行，新增权限码自动 seed；缺这步导致
	// /api/v1/rbac/permissions 返回 500 "Table 'mxcwpp.permissions' doesn't exist"）
	if err := initRBACPermissions(db, logger); err != nil {
		logger.Warn("初始化 RBAC 权限失败", zap.Error(err))
	}

	// 初始化默认组件（始终执行，确保组件列表完整）
	if err := initDefaultComponents(db, logger); err != nil {
		return fmt.Errorf("初始化默认组件失败: %w", err)
	}

	// 迁移 data/deps/ 下的旧依赖文件到 Component 表（仅运行一次）
	if err := migrateDepFiles(db, logger); err != nil {
		logger.Warn("迁移依赖文件失败", zap.Error(err))
	}

	// 初始化默认插件配置（始终执行，确保插件配置存在）
	if err := initDefaultPluginConfigs(db, logger, pluginsCfg); err != nil {
		return fmt.Errorf("初始化默认插件配置失败: %w", err)
	}

	// 初始化默认 FIM 策略（始终执行，仅在表为空时插入）
	if err := initDefaultFIMPolicies(db, logger); err != nil {
		return fmt.Errorf("初始化默认 FIM 策略失败: %w", err)
	}

	// 初始化内置检测规则（仅在表为空时插入）
	if err := initBuiltinDetectionRules(db, logger); err != nil {
		logger.Warn("初始化内置检测规则失败", zap.Error(err))
	}

	// 初始化内置容器基线规则（增量导入）
	if err := initKubeBaselineRules(db, logger); err != nil {
		logger.Warn("初始化内置容器基线规则失败", zap.Error(err))
	}

	// 初始化内置 CEL 表达式模板（增量导入）
	if err := initKubeExpressionTemplates(db, logger); err != nil {
		logger.Warn("初始化内置 CEL 表达式模板失败", zap.Error(err))
	}

	// 默认扫描计划
	var scheduleCount int64
	db.Model(&model.ScanSchedule{}).Count(&scheduleCount)
	if scheduleCount == 0 {
		schedules := []model.ScanSchedule{
			{Name: "每日漏洞库同步", ScanType: "sync_only", CronExpr: "0 0 2 * * *", Enabled: true, CreatedBy: "system"},
			{Name: "每周全量扫描", ScanType: "full_scan", CronExpr: "0 0 3 * * 0", Enabled: true, CreatedBy: "system"},
		}
		for _, s := range schedules {
			db.Create(&s)
		}
		logger.Info("初始化默认扫描计划")
	}

	// 初始化漏洞数据源 seed（13 个 source，UI 可启用/禁用）
	if err := initVulnDataSources(db, logger); err != nil {
		logger.Warn("初始化漏洞数据源失败", zap.Error(err))
	}

	// 每次启动幂等同步基线策略库。内置规则以 JSON 文件为准：
	// 检查/修复配置每次覆盖，但保留用户在 UI 上设置的 enabled 开关。
	// 新增 JSON 文件重启即自动入库；屏蔽内置规则请用「禁用」而非删除（删除后重启会重建）。
	if err := initDefaultPolicyGroup(db, logger); err != nil {
		return fmt.Errorf("初始化默认策略组失败: %w", err)
	}

	if policyDir == "" {
		if _, err := os.Stat("/opt/mxcwpp/policies"); err == nil {
			policyDir = "/opt/mxcwpp/policies"
		} else {
			policyDir = "plugins/baseline/config"
		}
	}

	policies, err := loadPoliciesFromDir(policyDir, logger)
	if err != nil {
		logger.Warn("加载策略文件失败，跳过策略同步", zap.Error(err), zap.String("policy_dir", policyDir))
	} else {
		ruleTotal := 0
		for _, policy := range policies {
			n, err := savePolicyToDB(db, policy, DefaultPolicyGroupID, logger)
			if err != nil {
				return fmt.Errorf("同步策略 %s 失败: %w", policy.ID, err)
			}
			ruleTotal += n
		}
		logger.Info("基线策略库同步完成",
			zap.String("policy_dir", policyDir),
			zap.Int("policy_count", len(policies)),
			zap.Int("rule_count", ruleTotal))
	}

	return nil
}

// SeedFeatureFlags 启动时插入内置 feature flag 默认值；已存在不覆盖。
func SeedFeatureFlags(db *gorm.DB, logger *zap.Logger) {
	for _, s := range model.DefaultFeatureFlags {
		ff := model.FeatureFlag{
			Key:         s.Key,
			Value:       s.Default,
			DefaultVal:  s.Default,
			Description: s.Description,
		}
		// 仅插入新 key，不覆盖已有运行时值
		if err := db.Where("flag_key = ?", s.Key).
			Attrs(ff).
			FirstOrCreate(&model.FeatureFlag{}).Error; err != nil {
			logger.Warn("seed feature_flag 失败", zap.String("key", s.Key), zap.Error(err))
		}
	}
	logger.Info("feature_flags 默认值已 seed", zap.Int("count", len(model.DefaultFeatureFlags)))
}

// SeedRetentionPolicies 启动时插入内置 retention policy 默认值。
func SeedRetentionPolicies(db *gorm.DB, logger *zap.Logger) {
	for _, s := range model.DefaultRetentionPolicies {
		rp := model.RetentionPolicy{
			CHTable:       s.CHTable,
			DisplayName:   s.DisplayName,
			Description:   s.Description,
			RetentionDays: s.Days,
		}
		if err := db.Where("ch_table = ?", s.CHTable).
			Attrs(rp).
			FirstOrCreate(&model.RetentionPolicy{}).Error; err != nil {
			logger.Warn("seed retention_policy 失败", zap.String("ch_table", s.CHTable), zap.Error(err))
		}
	}
	logger.Info("retention_policies 默认值已 seed", zap.Int("count", len(model.DefaultRetentionPolicies)))
}

// initDefaultUsers 初始化默认用户
// initDefaultTenant 创建/确保默认租户 t-default 存在。
// v1.x 升级到 v2.0 时，所有历史 User / Host / Alert / Vuln / ... 数据均归属此租户。
// 后续可通过 mxctl tenant create 创建新租户进行业务隔离。
func initDefaultTenant(db *gorm.DB, logger *zap.Logger) error {
	var t model.Tenant
	err := db.Where("id = ?", model.DefaultTenantID).First(&t).Error
	if err == nil {
		// 已存在 → 仅确保 status=active 且默认模式仍是 observe
		if t.Status != model.TenantStatusActive {
			t.Status = model.TenantStatusActive
			if e := db.Save(&t).Error; e != nil {
				return fmt.Errorf("更新默认租户状态失败: %w", e)
			}
			logger.Info("默认租户状态已恢复为 active", zap.String("tenant_id", model.DefaultTenantID))
		}
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("查询默认租户失败: %w", err)
	}

	t = model.Tenant{
		ID:                  model.DefaultTenantID,
		Name:                "Default Tenant",
		Type:                model.TenantTypeInternal,
		Status:              model.TenantStatusActive,
		DefaultMode:         model.TenantModeObserve, // 默认监听模式，详见 docs/operating-modes.md
		MLEnabled:           true,
		LLMEnabled:          false,
		QuotaAgents:         10000, // 默认租户配额放宽，避免升级期间触发限制
		QuotaLLMUSD:         1000.00,
		QuotaEventsDay:      10000000000,
		RetentionAlertsDays: 90,
		RetentionEventsDays: 30,
		RetentionAuditDays:  180,
		IsolationStrategy:   model.IsolationShared,
	}
	if err := db.Create(&t).Error; err != nil {
		return fmt.Errorf("创建默认租户失败: %w", err)
	}
	logger.Info("默认租户初始化成功",
		zap.String("tenant_id", t.ID),
		zap.String("mode", string(t.DefaultMode)),
	)
	return nil
}

func initDefaultUsers(db *gorm.DB, logger *zap.Logger) error {
	// 检查admin用户是否存在
	var adminUser model.User
	err := db.Where("username = ?", "admin").First(&adminUser).Error

	if err == nil {
		// admin用户已存在，检查状态并确保为active
		if adminUser.Status != model.UserStatusActive {
			adminUser.Status = model.UserStatusActive
			if err := db.Save(&adminUser).Error; err != nil {
				return fmt.Errorf("更新admin用户状态失败: %w", err)
			}
			logger.Info("admin用户状态已更新为active", zap.String("username", adminUser.Username))
		} else {
			logger.Info("admin用户已存在且状态正常", zap.String("username", adminUser.Username))
		}
		return nil
	}

	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("检查admin用户失败: %w", err)
	}

	// admin用户不存在，创建默认管理员用户（admin/admin123）
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("加密密码失败: %w", err)
	}

	defaultUser := &model.User{
		TenantID:            model.DefaultTenantID,
		Username:            "admin",
		Password:            string(hashedPassword),
		Email:               "admin@example.com",
		Role:                model.UserRoleAdmin,
		IsPlatformAdmin:     true, // admin 默认是平台超管，可访问 /api/v2/admin/* 路径
		Status:              model.UserStatusActive,
		ForceChangePassword: true,
	}

	if err := db.Create(defaultUser).Error; err != nil {
		return fmt.Errorf("创建默认用户失败: %w", err)
	}

	logger.Info("默认用户初始化成功", zap.String("username", defaultUser.Username))
	return nil
}

// skipPolicyDirs 主机基线同步时跳过的子目录：
// windows 非 Linux；cis-k8s/cis-docker 属容器基线，走 KubeBaselineRule 独立入库路径。
var skipPolicyDirs = map[string]bool{
	"windows":    true,
	"cis-k8s":    true,
	"cis-docker": true,
}

// loadPoliciesFromDir 递归加载目录下所有策略 JSON 文件（跳过非 Linux / 容器目录）
func loadPoliciesFromDir(dir string, logger *zap.Logger) ([]*engine.Policy, error) {
	var policies []*engine.Policy

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipPolicyDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(d.Name()) != ".json" {
			return nil
		}

		data, rerr := os.ReadFile(path)
		if rerr != nil {
			logger.Warn("读取策略文件失败", zap.Error(rerr), zap.String("file", path))
			return nil
		}

		var policy engine.Policy
		if jerr := json.Unmarshal(data, &policy); jerr != nil {
			logger.Warn("解析策略文件失败", zap.Error(jerr), zap.String("file", path))
			return nil
		}

		// 跳过空策略（如占位的 weakpassword.json，无规则）
		if policy.ID == "" || len(policy.Rules) == 0 {
			logger.Warn("跳过空策略文件", zap.String("file", path), zap.String("policy_id", policy.ID))
			return nil
		}

		logger.Info("加载策略文件", zap.String("file", path), zap.Int("rules", len(policy.Rules)))
		policies = append(policies, &policy)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历策略目录失败: %w", err)
	}

	return policies, nil
}

// savePolicyToDB 幂等同步内置策略到数据库，返回写入的规则数。
// 隔离原则：
//   - 内置策略/规则（builtin=true）以 JSON 文件为准，每次启动覆盖元数据/检查/修复配置；
//   - 但保留用户设置的 enabled 开关；
//   - 若某 ID 已被用户自定义（builtin=false）占用，则跳过、绝不覆盖，保证不干扰用户规则。
func savePolicyToDB(db *gorm.DB, policy *engine.Policy, groupID string, logger *zap.Logger) (int, error) {
	// 默认 RuntimeTypes=["vm"]（仅虚拟机适用），确保 Linux 主机基线不应用于容器
	dbPolicy := &model.Policy{
		ID:           policy.ID,
		Name:         policy.Name,
		Version:      policy.Version,
		Description:  policy.Description,
		OSFamily:     model.StringArray(policy.OSFamily),
		OSVersion:    policy.OSVersion,
		RuntimeTypes: model.StringArray{"vm"},
		Enabled:      policy.Enabled,
		Builtin:      true,
		GroupID:      groupID,
	}

	var existing model.Policy
	err := db.Where("id = ?", policy.ID).First(&existing).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		if cErr := db.Create(dbPolicy).Error; cErr != nil {
			return 0, fmt.Errorf("创建策略失败: %w", cErr)
		}
	case err != nil:
		return 0, fmt.Errorf("查询策略失败: %w", err)
	case !existing.Builtin:
		// ID 已被用户自定义策略占用 → 跳过整个策略，绝不覆盖用户数据
		logger.Warn("策略 ID 被用户自定义占用，跳过内置同步",
			zap.String("policy_id", policy.ID))
		return 0, nil
	default:
		// 内置策略已存在：覆盖元数据，保留 enabled（用户开关）
		if uErr := db.Model(&existing).Select(
			"name", "version", "description", "os_family", "os_version", "runtime_types", "group_id", "builtin",
		).Updates(dbPolicy).Error; uErr != nil {
			return 0, fmt.Errorf("更新策略失败: %w", uErr)
		}
	}

	count := 0
	for _, rule := range policy.Rules {
		checkConfig := model.CheckConfig{
			Condition: rule.Check.Condition,
			Rules:     make([]model.CheckRule, len(rule.Check.Rules)),
		}
		for i, cr := range rule.Check.Rules {
			checkRule := model.CheckRule{Type: cr.Type, Param: cr.Param}
			if cr.Result != "" {
				checkRule.Result = cr.Result
			}
			checkConfig.Rules[i] = checkRule
		}

		fixConfig := model.FixConfig{
			Suggestion:      rule.Fix.Suggestion,
			Command:         rule.Fix.Command,
			RestartServices: rule.Fix.RestartServices,
		}

		dbRule := &model.Rule{
			RuleID:      rule.RuleID,
			PolicyID:    policy.ID,
			Category:    rule.Category,
			Title:       rule.Title,
			Description: rule.Description,
			Severity:    rule.Severity,
			Enabled:     true, // 仅新建时生效；已存在规则保留用户开关
			Builtin:     true,
			CheckConfig: checkConfig,
			FixConfig:   fixConfig,
		}

		var existingRule model.Rule
		rErr := db.Where("rule_id = ?", rule.RuleID).First(&existingRule).Error
		switch {
		case rErr == gorm.ErrRecordNotFound:
			if cErr := db.Create(dbRule).Error; cErr != nil {
				return count, fmt.Errorf("创建规则 %s 失败: %w", rule.RuleID, cErr)
			}
		case rErr != nil:
			return count, fmt.Errorf("查询规则 %s 失败: %w", rule.RuleID, rErr)
		case !existingRule.Builtin:
			// rule_id 被用户自定义规则占用 → 跳过，绝不覆盖
			logger.Warn("规则 ID 被用户自定义占用，跳过内置同步",
				zap.String("rule_id", rule.RuleID))
			continue
		default:
			// 内置规则已存在：覆盖检查/修复配置，保留 enabled
			if uErr := db.Model(&existingRule).Select(
				"policy_id", "category", "title", "description", "severity", "check_config", "fix_config", "builtin",
			).Updates(dbRule).Error; uErr != nil {
				return count, fmt.Errorf("更新规则 %s 失败: %w", rule.RuleID, uErr)
			}
		}
		count++
	}

	// reconcile：删除该策略下已从 JSON 移除的内置规则（用户自定义 builtin=false 不动）
	jsonRuleIDs := make([]string, 0, len(policy.Rules))
	for _, r := range policy.Rules {
		jsonRuleIDs = append(jsonRuleIDs, r.RuleID)
	}
	if len(jsonRuleIDs) > 0 {
		del := db.Where("policy_id = ? AND builtin = ? AND rule_id NOT IN ?", policy.ID, true, jsonRuleIDs).
			Delete(&model.Rule{})
		if del.Error != nil {
			return count, fmt.Errorf("清理策略 %s 过期内置规则失败: %w", policy.ID, del.Error)
		}
		if del.RowsAffected > 0 {
			logger.Info("清理过期内置规则",
				zap.String("policy_id", policy.ID),
				zap.Int64("removed", del.RowsAffected))
		}
	}

	return count, nil
}

// initDefaultPolicyGroup 初始化默认策略组
func initDefaultPolicyGroup(db *gorm.DB, logger *zap.Logger) error {
	// 检查默认策略组是否存在
	var group model.PolicyGroup
	err := db.Where("id = ?", DefaultPolicyGroupID).First(&group).Error

	if err == nil {
		// 默认策略组已存在
		logger.Info("默认策略组已存在", zap.String("group_id", DefaultPolicyGroupID), zap.String("name", group.Name))
		return nil
	}

	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("检查默认策略组失败: %w", err)
	}

	// 创建默认策略组
	defaultGroup := &model.PolicyGroup{
		ID:          DefaultPolicyGroupID,
		Name:        "主机系统基线组",
		Description: "系统内置的基线检查策略组，包含 Linux 主机操作系统安全基线检查策略（仅适用于主机/虚拟机，不适用于容器）",
		Icon:        "🖥",
		Color:       "#1890ff",
		SortOrder:   0,
		Enabled:     true,
	}

	if err := db.Create(defaultGroup).Error; err != nil {
		return fmt.Errorf("创建默认策略组失败: %w", err)
	}

	logger.Info("默认策略组初始化成功",
		zap.String("group_id", defaultGroup.ID),
		zap.String("name", defaultGroup.Name),
	)
	return nil
}

// initDefaultPluginConfigs 初始化默认插件配置
func initDefaultPluginConfigs(db *gorm.DB, logger *zap.Logger, pluginsCfg *config.PluginsConfig) error {
	managedPlugins := []managedPluginBootstrap{
		{
			Name:         "baseline",
			Type:         model.PluginTypeBaseline,
			RuntimeTypes: model.StringArray{"vm"},
			Description:  "Linux 基线安全检查插件，执行操作系统安全配置检查",
			Detail:       `{"check_interval": 3600}`,
		},
		{
			Name:         "collector",
			Type:         model.PluginTypeCollector,
			RuntimeTypes: model.StringArray{"vm", "docker", "k8s"},
			Description:  "资产采集插件，采集主机进程、端口、用户等信息",
			Detail:       `{"collect_interval": 300}`,
		},
		{
			Name:         "fim",
			Type:         model.PluginTypeFIM,
			RuntimeTypes: model.StringArray{"vm"},
			Description:  "文件完整性监控插件，基于 AIDE 检测文件变更",
			Detail:       `{"check_timeout_minutes": 30}`,
		},
		{
			Name:         "scanner",
			Type:         model.PluginTypeScanner,
			RuntimeTypes: model.StringArray{"vm"},
			Description:  "病毒查杀插件，基于 ClamAV + YARA-X 双引擎检测恶意文件",
			Detail:       `{"quarantine_dir": "/var/mxcwpp/quarantine", "yara_rules_dir": "/var/mxcwpp/yara-rules"}`,
		},
	}

	for _, plugin := range managedPlugins {
		if err := ensureManagedPluginConfig(db, logger, pluginsCfg, plugin); err != nil {
			return err
		}
	}

	return nil
}

func ensureManagedPluginConfig(db *gorm.DB, logger *zap.Logger, pluginsCfg *config.PluginsConfig, plugin managedPluginBootstrap) error {
	var existing model.PluginConfig
	err := db.Where("name = ?", plugin.Name).First(&existing).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return fmt.Errorf("检查插件配置 %s 失败: %w", plugin.Name, err)
	}
	hasExisting := err == nil

	version, pkg, found, err := findLatestUploadedPluginPackage(db, plugin.Name)
	if err != nil {
		return fmt.Errorf("查询插件 %s 上传包失败: %w", plugin.Name, err)
	}

	if !found {
		if hasExisting {
			// 包不存在不再禁用: Agent 端可能已有本地 cache (历史下载),
			// 仍发 config 走 cache 启动. download_urls 保留指向 manager,
			// 让新装 Agent 能感知缺包(下载 404 后管理员补传).
			downloadURL := buildManagedPluginDownloadURL(pluginsCfg, plugin.Name)
			updates := map[string]interface{}{
				"download_urls": model.StringArray{downloadURL},
				"runtime_types": plugin.RuntimeTypes,
				"description":   plugin.Description,
				"detail":        plugin.Detail,
			}
			if err := db.Model(&existing).Updates(updates).Error; err != nil {
				return fmt.Errorf("更新插件配置 %s 失败: %w", plugin.Name, err)
			}
			logger.Info("插件包未上传, 保留 config 让 Agent 端走本地 cache",
				zap.String("name", plugin.Name),
				zap.String("current_version", existing.Version),
			)
		} else {
			logger.Debug("插件尚未上传，跳过创建默认插件配置",
				zap.String("name", plugin.Name),
			)
		}
		return nil
	}

	downloadURL := buildManagedPluginDownloadURL(pluginsCfg, plugin.Name)
	detail := fmt.Sprintf(`{"source":"component_upload","updated_at":"%s"}`, time.Now().Format(time.RFC3339))

	if !hasExisting {
		pluginConfig := model.PluginConfig{
			Name:         plugin.Name,
			Type:         plugin.Type,
			Version:      version.Version,
			SHA256:       pkg.SHA256,
			DownloadURLs: model.StringArray{downloadURL},
			RuntimeTypes: plugin.RuntimeTypes,
			Detail:       detail,
			Enabled:      true,
			Description:  plugin.Description,
		}
		if err := db.Create(&pluginConfig).Error; err != nil {
			return fmt.Errorf("创建插件配置 %s 失败: %w", plugin.Name, err)
		}
		logger.Info("根据已上传组件包创建插件配置",
			zap.String("name", plugin.Name),
			zap.String("version", version.Version),
			zap.String("download_url", downloadURL),
		)
		return nil
	}

	updates := map[string]interface{}{
		"type":          plugin.Type,
		"version":       version.Version,
		"sha256":        pkg.SHA256,
		"download_urls": model.StringArray{downloadURL},
		"runtime_types": plugin.RuntimeTypes,
		"detail":        detail,
		"enabled":       true,
		"description":   plugin.Description,
	}
	if err := db.Model(&existing).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新插件配置 %s 失败: %w", plugin.Name, err)
	}
	logger.Info("根据已上传组件包同步插件配置",
		zap.String("name", plugin.Name),
		zap.String("version", version.Version),
		zap.String("download_url", downloadURL),
	)
	return nil
}

func findLatestUploadedPluginPackage(db *gorm.DB, pluginName string) (model.ComponentVersion, model.ComponentPackage, bool, error) {
	var component model.Component
	if err := db.Where("name = ? AND category = ?", pluginName, model.ComponentCategoryPlugin).First(&component).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return model.ComponentVersion{}, model.ComponentPackage{}, false, nil
		}
		return model.ComponentVersion{}, model.ComponentPackage{}, false, err
	}

	var version model.ComponentVersion
	if err := db.Where("component_id = ? AND is_latest = ?", component.ID, true).First(&version).Error; err != nil {
		if err := db.Where("component_id = ?", component.ID).Order("created_at DESC").First(&version).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return model.ComponentVersion{}, model.ComponentPackage{}, false, nil
			}
			return model.ComponentVersion{}, model.ComponentPackage{}, false, err
		}
	}

	var pkg model.ComponentPackage
	if err := db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
		version.ID, model.PackageTypeBinary, "amd64", true).First(&pkg).Error; err != nil {
		if err := db.Where("version_id = ? AND pkg_type = ? AND enabled = ?",
			version.ID, model.PackageTypeBinary, true).First(&pkg).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return model.ComponentVersion{}, model.ComponentPackage{}, false, nil
			}
			return model.ComponentVersion{}, model.ComponentPackage{}, false, err
		}
	}

	info, err := os.Stat(pkg.FilePath)
	if err != nil || info.IsDir() {
		return model.ComponentVersion{}, model.ComponentPackage{}, false, nil
	}

	return version, pkg, true, nil
}

func buildManagedPluginDownloadURL(pluginsCfg *config.PluginsConfig, pluginName string) string {
	// 始终使用相对路径，由 AC 端根据 backend_url 动态拼接完整地址
	return fmt.Sprintf("/api/v1/plugins/download/%s", pluginName)
}

// initDefaultFIMPolicies 初始化默认 FIM 策略
// 仅在 fim_policies 表为空时插入，避免重复创建
func initDefaultFIMPolicies(db *gorm.DB, logger *zap.Logger) error {
	var count int64
	if err := db.Model(&model.FIMPolicy{}).Count(&count).Error; err != nil {
		// 表可能不存在（首次启动 AutoMigrate 之前），静默跳过
		logger.Debug("FIM 策略表查询失败，跳过初始化", zap.Error(err))
		return nil
	}

	if count > 0 {
		logger.Debug("FIM 策略已存在，跳过默认策略初始化", zap.Int64("count", count))
		return nil
	}

	defaultPolicies := []model.FIMPolicy{
		{
			PolicyID:    "fim-default-general",
			Name:        "通用文件完整性策略",
			Description: "监控关键系统二进制文件、认证配置文件和SSH配置等，适用于所有主机",
			WatchPaths: model.WatchPaths{
				{Path: "/bin", Level: "NORMAL", Comment: "系统命令"},
				{Path: "/sbin", Level: "NORMAL", Comment: "系统管理命令"},
				{Path: "/usr/bin", Level: "NORMAL", Comment: "用户态命令"},
				{Path: "/usr/sbin", Level: "NORMAL", Comment: "用户态管理命令"},
				{Path: "/etc/passwd", Level: "NORMAL", Comment: "用户文件"},
				{Path: "/etc/shadow", Level: "NORMAL", Comment: "密码文件"},
				{Path: "/etc/group", Level: "NORMAL", Comment: "组文件"},
				{Path: "/etc/gshadow", Level: "NORMAL", Comment: "组密码文件"},
				{Path: "/etc/sudoers", Level: "NORMAL", Comment: "提权配置"},
				{Path: "/etc/ssh/sshd_config", Level: "NORMAL", Comment: "SSH 服务配置"},
				{Path: "/etc/ssh/ssh_config", Level: "NORMAL", Comment: "SSH 客户端配置"},
				{Path: "/etc/crontab", Level: "NORMAL", Comment: "定时任务"},
				{Path: "/etc/pam.d", Level: "NORMAL", Comment: "PAM 认证配置"},
			},
			ExcludePaths: model.StringArray{
				"/usr/src",
				"/usr/tmp",
				"/var/log",
				"/tmp",
				"/boot/grub2/grubenv",
			},
			CheckIntervalHours: 24,
			TargetType:         "all",
			Enabled:            true,
		},
		{
			PolicyID:    "fim-default-database",
			Name:        "数据库服务器策略",
			Description: "监控 MySQL/MariaDB、Redis、PostgreSQL 的配置文件和认证文件，防止数据库配置被篡改",
			WatchPaths: model.WatchPaths{
				{Path: "/etc/my.cnf", Level: "NORMAL", Comment: "MySQL 主配置"},
				{Path: "/etc/my.cnf.d", Level: "NORMAL", Comment: "MySQL 配置目录"},
				{Path: "/etc/mysql", Level: "NORMAL", Comment: "MySQL/MariaDB 配置目录"},
				{Path: "/etc/redis.conf", Level: "NORMAL", Comment: "Redis 主配置"},
				{Path: "/etc/redis", Level: "NORMAL", Comment: "Redis 配置目录"},
				{Path: "/etc/redis-sentinel.conf", Level: "NORMAL", Comment: "Redis Sentinel 配置"},
				{Path: "/var/lib/pgsql/data/pg_hba.conf", Level: "NORMAL", Comment: "PostgreSQL 认证配置"},
				{Path: "/var/lib/pgsql/data/postgresql.conf", Level: "NORMAL", Comment: "PostgreSQL 主配置"},
			},
			ExcludePaths: model.StringArray{
				"/var/lib/mysql",
				"/var/lib/redis",
				"/var/lib/pgsql/data/base",
				"/var/lib/pgsql/data/pg_wal",
			},
			CheckIntervalHours: 24,
			TargetType:         "all",
			Enabled:            false,
		},
		{
			PolicyID:    "fim-default-webserver",
			Name:        "Web 服务器策略",
			Description: "监控 Nginx/Apache/OpenResty 的配置文件和 SSL 证书，防止 Web 配置和证书被篡改",
			WatchPaths: model.WatchPaths{
				{Path: "/etc/nginx", Level: "NORMAL", Comment: "Nginx 配置目录"},
				{Path: "/usr/local/nginx/conf", Level: "NORMAL", Comment: "Nginx 自编译配置"},
				{Path: "/usr/local/openresty/nginx/conf", Level: "NORMAL", Comment: "OpenResty 配置"},
				{Path: "/etc/httpd/conf", Level: "NORMAL", Comment: "Apache 主配置"},
				{Path: "/etc/httpd/conf.d", Level: "NORMAL", Comment: "Apache 扩展配置"},
				{Path: "/etc/pki/tls/certs", Level: "NORMAL", Comment: "TLS 证书"},
				{Path: "/etc/pki/tls/private", Level: "NORMAL", Comment: "TLS 私钥"},
				{Path: "/etc/ssl/certs", Level: "NORMAL", Comment: "SSL 证书"},
				{Path: "/etc/ssl/private", Level: "NORMAL", Comment: "SSL 私钥"},
			},
			ExcludePaths: model.StringArray{
				"/usr/local/openresty/nginx/logs",
				"/usr/local/nginx/logs",
				"/var/log/nginx",
				"/var/log/httpd",
			},
			CheckIntervalHours: 24,
			TargetType:         "all",
			Enabled:            false,
		},
		{
			PolicyID:    "fim-default-container",
			Name:        "容器宿主机策略",
			Description: "监控 Docker/containerd 守护进程配置和运行时关键文件，防止容器运行环境被篡改",
			WatchPaths: model.WatchPaths{
				{Path: "/etc/docker/daemon.json", Level: "NORMAL", Comment: "Docker 守护进程配置"},
				{Path: "/etc/containerd", Level: "NORMAL", Comment: "containerd 配置目录"},
				{Path: "/usr/lib/systemd/system/docker.service", Level: "NORMAL", Comment: "Docker 服务单元"},
				{Path: "/usr/lib/systemd/system/containerd.service", Level: "NORMAL", Comment: "containerd 服务单元"},
				{Path: "/etc/crictl.yaml", Level: "NORMAL", Comment: "CRI 工具配置"},
			},
			ExcludePaths: model.StringArray{
				"/var/lib/docker",
				"/var/lib/containerd",
			},
			CheckIntervalHours: 24,
			TargetType:         "all",
			Enabled:            false,
		},
		{
			PolicyID:    "fim-default-middleware",
			Name:        "中间件与应用服务器策略",
			Description: "监控 Tomcat、Kafka、Zookeeper 等中间件的配置文件和启动脚本",
			WatchPaths: model.WatchPaths{
				{Path: "/etc/tomcat", Level: "NORMAL", Comment: "Tomcat 配置目录"},
				{Path: "/etc/kafka", Level: "NORMAL", Comment: "Kafka 配置目录"},
				{Path: "/etc/zookeeper", Level: "NORMAL", Comment: "Zookeeper 配置目录"},
				{Path: "/etc/elasticsearch", Level: "NORMAL", Comment: "Elasticsearch 配置目录"},
				{Path: "/usr/lib/systemd/system", Level: "NORMAL", Comment: "systemd 服务单元"},
				{Path: "/etc/init.d", Level: "NORMAL", Comment: "SysV 启动脚本"},
				{Path: "/etc/systemd/system", Level: "NORMAL", Comment: "自定义 systemd 服务"},
				{Path: "/etc/ld.so.conf", Level: "NORMAL", Comment: "动态链接库配置"},
				{Path: "/etc/ld.so.conf.d", Level: "NORMAL", Comment: "动态链接库配置目录"},
			},
			ExcludePaths: model.StringArray{
				"/var/log",
				"/var/lib/elasticsearch",
				"/var/lib/kafka-logs",
			},
			CheckIntervalHours: 24,
			TargetType:         "all",
			Enabled:            false,
		},
	}

	for _, policy := range defaultPolicies {
		wantEnabled := policy.Enabled
		if err := db.Create(&policy).Error; err != nil {
			return fmt.Errorf("创建默认 FIM 策略 %s 失败: %w", policy.PolicyID, err)
		}
		// GORM 对 bool 零值（false）会跳过并走 DB default(1)，需要显式更新
		if !wantEnabled {
			db.Model(&model.FIMPolicy{}).Where("policy_id = ?", policy.PolicyID).Update("enabled", false)
		}
		logger.Info("默认 FIM 策略初始化成功",
			zap.String("policy_id", policy.PolicyID),
			zap.String("name", policy.Name),
			zap.Bool("enabled", wantEnabled),
		)
	}

	return nil
}

// builtinRuleYAML 内置规则 YAML 定义结构
type builtinRuleYAML struct {
	Rules []struct {
		Name        string   `mapstructure:"name"`
		Expression  string   `mapstructure:"expression"`
		Severity    string   `mapstructure:"severity"`
		Category    string   `mapstructure:"category"`
		MitreID     string   `mapstructure:"mitre_id"`
		DataTypes   []string `mapstructure:"data_types"`
		Description string   `mapstructure:"description"`
	} `mapstructure:"rules"`
}

// initBuiltinDetectionRules 初始化内置 CEL 检测规则
// 增量导入：新规则插入，已存在且未被用户修改的内置规则跟随版本更新
func initBuiltinDetectionRules(db *gorm.DB, logger *zap.Logger) error {
	// 从 embed 读取内置规则 YAML
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(string(builtinrules.BuiltinRulesYAML))); err != nil {
		return fmt.Errorf("解析内置规则 YAML 失败: %w", err)
	}

	var rulesFile builtinRuleYAML
	if err := v.Unmarshal(&rulesFile); err != nil {
		return fmt.Errorf("反序列化内置规则失败: %w", err)
	}

	// 查询已存在的内置规则，按 name 索引
	var existingRules []model.DetectionRule
	db.Where("builtin = ?", true).Find(&existingRules)
	existingMap := make(map[string]*model.DetectionRule, len(existingRules))
	for i := range existingRules {
		existingMap[existingRules[i].Name] = &existingRules[i]
	}

	imported, updated := 0, 0
	for _, r := range rulesFile.Rules {
		if existing, ok := existingMap[r.Name]; ok {
			// 已存在的内置规则：用户未修改过则跟随版本更新
			if !existing.UserModified {
				db.Model(existing).Updates(map[string]interface{}{
					"expression":  r.Expression,
					"severity":    r.Severity,
					"category":    r.Category,
					"mitre_id":    r.MitreID,
					"description": r.Description,
					"data_types":  model.StringArray(r.DataTypes),
				})
				updated++
			}
			continue
		}
		// 新规则：插入并标记为内置
		rule := model.DetectionRule{
			Name:        r.Name,
			Expression:  r.Expression,
			Severity:    r.Severity,
			Category:    r.Category,
			MitreID:     r.MitreID,
			Description: r.Description,
			DataTypes:   model.StringArray(r.DataTypes),
			Enabled:     true,
			Builtin:     true,
		}
		if err := db.Create(&rule).Error; err != nil {
			logger.Warn("导入内置规则失败", zap.String("name", r.Name), zap.Error(err))
			continue
		}
		imported++
	}

	logger.Info("内置检测规则同步完成",
		zap.Int("new", imported),
		zap.Int("updated", updated),
		zap.Int("existing", len(existingRules)),
	)
	return nil
}

// initDefaultComponents 初始化默认组件列表
// 确保所有预期组件在 components 表中存在，不存在则创建
func initDefaultComponents(db *gorm.DB, logger *zap.Logger) error {
	type componentDef struct {
		Name        string
		Category    model.ComponentCategory
		Description string
	}

	components := []componentDef{
		{Name: "agent", Category: model.ComponentCategoryAgent, Description: "矩阵云安全平台主机安全 Agent"},
		{Name: "baseline", Category: model.ComponentCategoryPlugin, Description: "Linux 基线安全检查插件，执行操作系统安全配置检查"},
		{Name: "collector", Category: model.ComponentCategoryPlugin, Description: "资产采集插件，采集主机进程、端口、用户等信息"},
		{Name: "fim", Category: model.ComponentCategoryPlugin, Description: "文件完整性监控插件，基于 AIDE 检测文件变更"},
		{Name: "scanner", Category: model.ComponentCategoryPlugin, Description: "病毒查杀插件，基于 ClamAV + YARA-X 双引擎检测恶意文件"},
		{Name: "remediation", Category: model.ComponentCategoryPlugin, Description: "漏洞修复插件，执行 yum/apt 包升级与系统补丁应用"},
		{Name: "virus-database", Category: model.ComponentCategoryPlugin, Description: "ClamAV 病毒特征库，由 freshclam 自动更新"},
	}

	for _, c := range components {
		var existing model.Component
		err := db.Where("name = ?", c.Name).First(&existing).Error
		if err == nil {
			// 已存在，跳过
			continue
		}
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("检查组件 %s 失败: %w", c.Name, err)
		}

		comp := model.Component{
			Name:        c.Name,
			Category:    c.Category,
			Description: c.Description,
			CreatedBy:   "system",
		}
		if err := db.Create(&comp).Error; err != nil {
			return fmt.Errorf("创建组件 %s 失败: %w", c.Name, err)
		}
		logger.Info("初始化组件成功", zap.String("name", c.Name), zap.String("category", string(c.Category)))
	}

	return nil
}

// depFileNamePattern 解析 {name}-v{version}-{arch}.tar.gz
var depFileNamePattern = regexp.MustCompile(`^([a-zA-Z0-9_-]+)-v([0-9][0-9a-zA-Z.\-]*)-(amd64|arm64)\.tar\.gz$`)

// migrateDepFiles 将 data/deps/ 下的旧依赖 tar.gz 文件迁移到 Component/Version/Package 模型
// 幂等：仅当 DB 中该版本的包记录不存在时才插入
func migrateDepFiles(db *gorm.DB, logger *zap.Logger) error {
	depsRoot := filepath.Join("data", "deps")
	if _, err := os.Stat(depsRoot); os.IsNotExist(err) {
		return nil
	}

	entries, err := os.ReadDir(depsRoot)
	if err != nil {
		return fmt.Errorf("读取 data/deps 失败: %w", err)
	}

	uploadsRoot := "uploads"
	migrated := 0

	for _, dirEntry := range entries {
		if !dirEntry.IsDir() {
			continue
		}
		depName := dirEntry.Name()

		// 查找对应的依赖组件
		var component model.Component
		if err := db.Where("name = ? AND category = ?", depName, model.ComponentCategoryDependency).First(&component).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				logger.Info("跳过未登记的依赖目录", zap.String("name", depName))
				continue
			}
			logger.Warn("查询依赖组件失败", zap.String("name", depName), zap.Error(err))
			continue
		}

		depDir := filepath.Join(depsRoot, depName)
		files, err := os.ReadDir(depDir)
		if err != nil {
			logger.Warn("读取依赖目录失败", zap.String("dir", depDir), zap.Error(err))
			continue
		}

		// 按版本号组织 {version} -> []{arch, srcPath, fileName}
		type pkgItem struct {
			arch     string
			srcPath  string
			fileName string
		}
		versionMap := make(map[string][]pkgItem)

		for _, f := range files {
			if f.IsDir() {
				continue
			}
			m := depFileNamePattern.FindStringSubmatch(f.Name())
			if m == nil {
				continue
			}
			name, ver, arch := m[1], m[2], m[3]
			if name != depName {
				continue
			}
			versionMap[ver] = append(versionMap[ver], pkgItem{
				arch:     arch,
				srcPath:  filepath.Join(depDir, f.Name()),
				fileName: f.Name(),
			})
		}

		if len(versionMap) == 0 {
			continue
		}

		// 创建版本和包记录
		for ver, items := range versionMap {
			var compVersion model.ComponentVersion
			err := db.Where("component_id = ? AND version = ?", component.ID, ver).First(&compVersion).Error
			if err == gorm.ErrRecordNotFound {
				compVersion = model.ComponentVersion{
					ComponentID: component.ID,
					Version:     ver,
					Changelog:   "从 data/deps 自动迁移",
					IsLatest:    true,
					CreatedBy:   "system",
				}
				if err := db.Create(&compVersion).Error; err != nil {
					logger.Warn("创建依赖版本失败",
						zap.String("name", depName), zap.String("version", ver), zap.Error(err))
					continue
				}
			} else if err != nil {
				logger.Warn("查询依赖版本失败", zap.Error(err))
				continue
			}

			// 准备目标目录
			dstDir := filepath.Join(uploadsRoot, "packages", depName, ver)
			if err := os.MkdirAll(dstDir, 0755); err != nil {
				logger.Warn("创建目标目录失败", zap.String("dir", dstDir), zap.Error(err))
				continue
			}

			for _, it := range items {
				// 检查是否已存在相同包记录
				var existing model.ComponentPackage
				err := db.Where("version_id = ? AND pkg_type = ? AND arch = ?",
					compVersion.ID, string(model.PackageTypeTGZ), it.arch).First(&existing).Error
				if err == nil {
					// 已有记录：确保文件路径存在即可，不重复操作
					continue
				}
				if err != gorm.ErrRecordNotFound {
					logger.Warn("查询依赖包失败", zap.Error(err))
					continue
				}

				dstFile := filepath.Join(dstDir, it.fileName)

				// 移动文件
				if err := os.Rename(it.srcPath, dstFile); err != nil {
					// 跨设备失败时尝试复制
					if copyErr := copyFile(it.srcPath, dstFile); copyErr != nil {
						logger.Warn("迁移文件失败", zap.String("src", it.srcPath), zap.Error(copyErr))
						continue
					}
					_ = os.Remove(it.srcPath)
				}

				// 计算 SHA256 与 大小
				sum, size, err := hashAndSize(dstFile)
				if err != nil {
					logger.Warn("计算文件哈希失败", zap.String("file", dstFile), zap.Error(err))
					continue
				}

				pkg := model.ComponentPackage{
					VersionID:  compVersion.ID,
					OS:         "linux",
					Arch:       it.arch,
					PkgType:    model.PackageTypeTGZ,
					FilePath:   dstFile,
					FileName:   it.fileName,
					FileSize:   size,
					SHA256:     sum,
					Enabled:    true,
					UploadedBy: "system",
				}
				if err := db.Create(&pkg).Error; err != nil {
					logger.Warn("创建依赖包记录失败", zap.Error(err))
					continue
				}
				migrated++
				logger.Info("迁移依赖包成功",
					zap.String("name", depName),
					zap.String("version", ver),
					zap.String("arch", it.arch),
					zap.String("dst", dstFile),
				)
			}
		}

		// 尝试清理空的目录
		if remain, _ := os.ReadDir(depDir); len(remain) == 0 {
			_ = os.Remove(depDir)
		}
	}

	// 如果 data/deps 整个空了，顺便清理
	if remain, _ := os.ReadDir(depsRoot); len(remain) == 0 {
		_ = os.Remove(depsRoot)
	}

	if migrated > 0 {
		logger.Info("依赖文件迁移完成", zap.Int("migrated_packages", migrated))
	}
	return nil
}

// hashAndSize 计算文件 SHA256 和大小
func hashAndSize(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// copyFile 复制文件内容
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

const cisBenchmarkVersion = "CIS Kubernetes Benchmark 1.8"

// builtinCheckConfigs 返回内置规则的 CEL 检查配置
// 跨资源查询或复杂逻辑的规则由 Go 函数处理，不在此定义
func builtinCheckConfigs() map[string]*model.KubeCheckConfig {
	return map[string]*model.KubeCheckConfig{
		// ===== RBAC 安全 =====
		"CIS-K8S-001": {ResourceType: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Namespace: "",
			Expression: `resource.subjects.exists(s, s.name == "system:anonymous" || s.name == "system:unauthenticated")`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-005": {ResourceType: "pods", Namespace: "!system",
			Expression: `(!has(resource.spec.serviceAccountName) || resource.spec.serviceAccountName == "" || resource.spec.serviceAccountName == "default") && (!has(resource.spec.automountServiceAccountToken) || resource.spec.automountServiceAccountToken == true)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-006": {ResourceType: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Namespace: "",
			Expression: `has(resource.roleRef) && resource.roleRef.name == "cluster-admin" && resource.metadata.name != "cluster-admin"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-007": {ResourceType: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Namespace: "",
			Expression: `!name.startsWith("system:") && name != "cluster-admin" && name != "admin" && name != "edit" && name != "view" && has(resource.rules) && resource.rules.exists(r, (has(r.verbs) && r.verbs.exists(v, v == "*")) || (has(r.resources) && r.resources.exists(res, res == "*")))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-008": {ResourceType: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Namespace: "",
			Expression: `!name.startsWith("system:") && has(resource.rules) && resource.rules.exists(r, has(r.resources) && r.resources.exists(res, res == "pods/exec" || res == "pods/attach"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-009": {ResourceType: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Namespace: "",
			Expression: `!name.startsWith("system:") && name != "cluster-admin" && name != "admin" && name != "edit" && name != "view" && has(resource.rules) && resource.rules.exists(r, has(r.resources) && r.resources.exists(res, res == "secrets" || res == "*") && has(r.verbs) && r.verbs.exists(v, v == "get" || v == "list" || v == "watch" || v == "*"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-010": {ResourceType: "clusterroles", APIGroup: "rbac.authorization.k8s.io", Namespace: "",
			Expression: `!name.startsWith("system:") && has(resource.rules) && resource.rules.exists(r, has(r.verbs) && r.verbs.exists(v, v == "escalate" || v == "bind" || v == "impersonate"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-011": {ResourceType: "serviceaccounts", Namespace: "!system",
			Expression: `name == "default" && (!has(resource.automountServiceAccountToken) || resource.automountServiceAccountToken == true)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-012": {ResourceType: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Namespace: "",
			Expression: `!name.startsWith("system:") && has(resource.subjects) && resource.subjects.exists(s, has(s.kind) && s.kind == "Group" && s.name == "system:masters")`, MatchPolicy: "any_match_fail"},

		// ===== Pod 安全 =====
		"CIS-K8S-003": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-004": {ResourceType: "pods", Namespace: "!system",
			Expression: `(has(resource.spec.hostNetwork) && resource.spec.hostNetwork == true) || (has(resource.spec.hostPID) && resource.spec.hostPID == true) || (has(resource.spec.hostIPC) && resource.spec.hostIPC == true)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-013": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.securityContext) || !has(c.securityContext.runAsNonRoot) || c.securityContext.runAsNonRoot != true)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-014": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.capabilities) && has(c.securityContext.capabilities.add) && c.securityContext.capabilities.add.exists(cap, cap == "ALL" || cap == "SYS_ADMIN" || cap == "NET_RAW" || cap == "SYS_PTRACE" || cap == "NET_ADMIN" || cap == "SYS_MODULE" || cap == "DAC_OVERRIDE"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-015": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.securityContext) || !has(c.securityContext.readOnlyRootFilesystem) || c.securityContext.readOnlyRootFilesystem != true)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-016": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.securityContext) || !has(c.securityContext.allowPrivilegeEscalation) || c.securityContext.allowPrivilegeEscalation != false)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-017": {ResourceType: "pods", Namespace: "!system",
			Expression: `has(resource.spec.volumes) && resource.spec.volumes.exists(v, has(v.hostPath))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-018": {ResourceType: "pods", Namespace: "*",
			Expression:  `has(resource.spec.volumes) && resource.spec.volumes.exists(v, has(v.hostPath) && (v.hostPath.path == "/var/run/docker.sock" || v.hostPath.path == "/run/containerd/containerd.sock" || v.hostPath.path == "/var/run/crio/crio.sock"))`,
			MatchPolicy: "any_match_fail"},
		"CIS-K8S-019": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, (!has(resource.spec.securityContext) || !has(resource.spec.securityContext.seccompProfile)) && (!has(c.securityContext) || !has(c.securityContext.seccompProfile)))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-020": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.resources) || !has(c.resources.limits) || !has(c.resources.limits.cpu))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-021": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.resources) || !has(c.resources.limits) || !has(c.resources.limits.memory))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-022": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.resources) || !has(c.resources.requests) || !has(c.resources.requests.cpu) || !has(c.resources.requests.memory))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-023": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.livenessProbe))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-024": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.readinessProbe))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-025": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, c.image.endsWith(":latest") || !c.image.contains(":"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-026": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !has(c.imagePullPolicy) || c.imagePullPolicy != "Always")`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-027": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, has(c.ports) && c.ports.exists(p, has(p.hostPort) && p.hostPort > 0))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-028": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.capabilities) && has(c.securityContext.capabilities.add) && size(c.securityContext.capabilities.add) > 0)`, MatchPolicy: "any_match_fail"},

		// ===== 网络安全 =====
		"CIS-K8S-002": {ResourceType: "networkpolicies", APIGroup: "networking.k8s.io", Namespace: "!system",
			Expression: `true`, MatchPolicy: "no_match_fail"},
		"CIS-K8S-029": {ResourceType: "networkpolicies", APIGroup: "networking.k8s.io", Namespace: "!system",
			Expression: `has(resource.spec.podSelector) && size(resource.spec.podSelector) == 0 && has(resource.spec.policyTypes) && resource.spec.policyTypes.exists(t, t == "Ingress") && (!has(resource.spec.ingress) || size(resource.spec.ingress) == 0)`, MatchPolicy: "no_match_fail"},
		"CIS-K8S-030": {ResourceType: "networkpolicies", APIGroup: "networking.k8s.io", Namespace: "!system",
			Expression: `has(resource.spec.podSelector) && size(resource.spec.podSelector) == 0 && has(resource.spec.policyTypes) && resource.spec.policyTypes.exists(t, t == "Egress") && (!has(resource.spec.egress) || size(resource.spec.egress) == 0)`, MatchPolicy: "no_match_fail"},
		"CIS-K8S-031": {ResourceType: "services", Namespace: "!system",
			Expression: `resource.spec.type == "NodePort"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-032": {ResourceType: "services", Namespace: "!system",
			Expression: `resource.spec.type == "LoadBalancer"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-033": {ResourceType: "services", Namespace: "*",
			Expression: `has(resource.spec.externalIPs) && size(resource.spec.externalIPs) > 0`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-034": {ResourceType: "ingresses", APIGroup: "networking.k8s.io", Namespace: "*",
			Expression: `!has(resource.spec.tls) || size(resource.spec.tls) == 0`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-035": {ResourceType: "services", Namespace: "!system",
			Expression: `resource.spec.type != "ExternalName" && (!has(resource.spec.selector) || size(resource.spec.selector) == 0)`, MatchPolicy: "any_match_fail"},

		// ===== 密钥与配置 =====
		"CIS-K8S-036": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, has(c.env) && c.env.exists(e, has(e.valueFrom) && has(e.valueFrom.secretKeyRef)))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-037": {ResourceType: "pods", Namespace: "*",
			Expression: `namespace == "default"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-038": {ResourceType: "deployments", APIGroup: "apps", Namespace: "*",
			Expression: `name == "tiller-deploy" || name.startsWith("tiller")`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-039": {ResourceType: "secrets", Namespace: "*",
			Expression: `has(resource.data) && size(resource.data) > 20`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-040": {ResourceType: "configmaps", Namespace: "!system",
			Expression: `has(resource.data) && size(resource.data) > 50`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-041": {ResourceType: "namespaces", Namespace: "",
			Expression: `size(labels) == 0 || !labels.exists(k, k != "name" && !k.contains("kubernetes.io/"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-042": {ResourceType: "secrets", Namespace: "!system",
			Expression: `resource.type == "kubernetes.io/service-account-token"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-043": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, has(c.env) && c.env.exists(e, has(e.value) && e.value != "" && !has(e.valueFrom) && (e.name.contains("PASSWORD") || e.name.contains("password") || e.name.contains("SECRET") || e.name.contains("secret") || e.name.contains("TOKEN") || e.name.contains("token") || e.name.contains("API_KEY") || e.name.contains("PRIVATE_KEY"))))`, MatchPolicy: "any_match_fail"},

		// ===== 工作负载安全 =====
		"CIS-K8S-044": {ResourceType: "deployments", APIGroup: "apps", Namespace: "!system",
			Expression: `!has(resource.spec.replicas) || resource.spec.replicas <= 1`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-045": {ResourceType: "deployments", APIGroup: "apps", Namespace: "!system",
			Expression: `has(resource.spec.replicas) && resource.spec.replicas > 1`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-046": {ResourceType: "cronjobs", APIGroup: "batch", Namespace: "!system",
			Expression: `!has(resource.spec.jobTemplate.spec.activeDeadlineSeconds)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-047": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !c.image.startsWith("registry.k8s.io/") && !c.image.startsWith("docker.io/") && !c.image.startsWith("gcr.io/") && !c.image.startsWith("ghcr.io/") && !c.image.startsWith("quay.io/") && !c.image.startsWith("mcr.microsoft.com/") && !c.image.startsWith("registry.cn-") && c.image.contains("/"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-049": {ResourceType: "daemonsets", APIGroup: "apps", Namespace: "!system",
			Expression: `resource.spec.template.spec.containers.exists(c, !has(c.resources) || !has(c.resources.limits) || !has(c.resources.limits.cpu) || !has(c.resources.limits.memory))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-050": {ResourceType: "jobs", APIGroup: "batch", Namespace: "!system",
			Expression: `!has(resource.spec.backoffLimit)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-051": {ResourceType: "deployments", APIGroup: "apps", Namespace: "!system",
			Expression: `has(resource.spec.strategy) && has(resource.spec.strategy.type) && resource.spec.strategy.type == "Recreate"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-052": {ResourceType: "statefulsets", APIGroup: "apps", Namespace: "!system",
			Expression: `!has(resource.spec.volumeClaimTemplates) || size(resource.spec.volumeClaimTemplates) == 0`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-053": {ResourceType: "deployments", APIGroup: "apps", Namespace: "!system",
			Expression: `has(resource.spec.replicas) && resource.spec.replicas > 1 && (!has(resource.spec.template.spec.affinity) || !has(resource.spec.template.spec.affinity.podAntiAffinity))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-054": {ResourceType: "deployments", APIGroup: "apps", Namespace: "!system",
			Expression: `has(resource.spec.replicas) && resource.spec.replicas > 1 && (!has(resource.spec.template.spec.topologySpreadConstraints) || size(resource.spec.template.spec.topologySpreadConstraints) == 0)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-055": {ResourceType: "deployments", APIGroup: "apps", Namespace: "!system",
			Expression: `has(resource.spec.replicas) && resource.spec.replicas > 1`, MatchPolicy: "any_match_fail"},

		// ===== 节点安全 =====
		"CIS-K8S-048": {ResourceType: "horizontalpodautoscalers", APIGroup: "autoscaling", Namespace: "!system",
			Expression: `!has(resource.spec.minReplicas) || resource.spec.minReplicas <= 1`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-056": {ResourceType: "nodes", Namespace: "",
			Expression: `resource.status.conditions.exists(c, c.type == "Ready" && c.status != "True")`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-057": {ResourceType: "nodes", Namespace: "",
			Expression: `resource.status.conditions.exists(c, (c.type == "MemoryPressure" || c.type == "DiskPressure" || c.type == "PIDPressure") && c.status == "True")`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-058": {ResourceType: "nodes", Namespace: "",
			Expression: `has(resource.status) && has(resource.status.nodeInfo) && has(resource.status.nodeInfo.kernelVersion) && (resource.status.nodeInfo.kernelVersion.startsWith("3.") || resource.status.nodeInfo.kernelVersion.startsWith("2.") || resource.status.nodeInfo.kernelVersion.startsWith("4.1.") || resource.status.nodeInfo.kernelVersion.startsWith("4.0.") || resource.status.nodeInfo.kernelVersion.startsWith("4.2.") || resource.status.nodeInfo.kernelVersion.startsWith("4.3.") || resource.status.nodeInfo.kernelVersion.startsWith("4.4.") || resource.status.nodeInfo.kernelVersion.startsWith("4.5.") || resource.status.nodeInfo.kernelVersion.startsWith("4.6.") || resource.status.nodeInfo.kernelVersion.startsWith("4.7.") || resource.status.nodeInfo.kernelVersion.startsWith("4.8.") || resource.status.nodeInfo.kernelVersion.startsWith("4.9.") || resource.status.nodeInfo.kernelVersion.startsWith("4.10.") || resource.status.nodeInfo.kernelVersion.startsWith("4.11.") || resource.status.nodeInfo.kernelVersion.startsWith("4.12.") || resource.status.nodeInfo.kernelVersion.startsWith("4.13.") || resource.status.nodeInfo.kernelVersion.startsWith("4.14.") || resource.status.nodeInfo.kernelVersion.startsWith("4.15.") || resource.status.nodeInfo.kernelVersion.startsWith("4.16.") || resource.status.nodeInfo.kernelVersion.startsWith("4.17.") || resource.status.nodeInfo.kernelVersion.startsWith("4.18."))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-059": {ResourceType: "nodes", Namespace: "",
			Expression: `has(resource.status) && has(resource.status.nodeInfo) && has(resource.status.nodeInfo.containerRuntimeVersion) && resource.status.nodeInfo.containerRuntimeVersion.startsWith("docker://")`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-060": {ResourceType: "nodes", Namespace: "",
			Expression: `has(resource.status) && has(resource.status.conditions) && resource.status.conditions.exists(c, c.type == "Ready" && c.status == "True") && has(resource.status.allocatable)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-061": {ResourceType: "nodes", Namespace: "",
			Expression: `has(resource.spec.unschedulable) && resource.spec.unschedulable == true`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-062": {ResourceType: "nodes", Namespace: "",
			Expression:  `has(resource.spec.taints) && resource.spec.taints.exists(t, t.effect == "NoExecute" && t.key != "node.kubernetes.io/not-ready" && t.key != "node.kubernetes.io/unreachable")`,
			MatchPolicy: "any_match_fail"},
		"CIS-K8S-063": {ResourceType: "pods", Namespace: "!system",
			Expression: `!has(resource.metadata.ownerReferences) || size(resource.metadata.ownerReferences) == 0`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-064": {ResourceType: "nodes", Namespace: "",
			Expression: `has(resource.status) && has(resource.status.allocatable) && has(resource.status.allocatable.pods)`, MatchPolicy: "any_match_fail"},

		// ===== 集群配置 =====
		"CIS-K8S-065": {ResourceType: "nodes", Namespace: "",
			Expression: `has(resource.status) && has(resource.status.nodeInfo) && has(resource.status.nodeInfo.kubeletVersion) && (resource.status.nodeInfo.kubeletVersion.startsWith("v1.2") && !resource.status.nodeInfo.kubeletVersion.startsWith("v1.28") && !resource.status.nodeInfo.kubeletVersion.startsWith("v1.29"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-066": {ResourceType: "namespaces", Namespace: "",
			Expression: `!name.startsWith("kube-") && name != "default"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-067": {ResourceType: "namespaces", Namespace: "",
			Expression: `!name.startsWith("kube-") && name != "default"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-068": {ResourceType: "namespaces", Namespace: "",
			Expression: `!labels.exists(k, k.startsWith("pod-security.kubernetes.io/"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-069": {ResourceType: "validatingwebhookconfigurations", APIGroup: "admissionregistration.k8s.io", Namespace: "",
			Expression: `true`, MatchPolicy: "no_match_fail"},
		"CIS-K8S-070": {ResourceType: "mutatingwebhookconfigurations", APIGroup: "admissionregistration.k8s.io", Namespace: "",
			Expression: `has(resource.webhooks) && resource.webhooks.exists(w, has(w.timeoutSeconds) && w.timeoutSeconds > 10)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-071": {ResourceType: "namespaces", Namespace: "",
			Expression: `!name.startsWith("kube-") && name != "default"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-072": {ResourceType: "persistentvolumes", Namespace: "",
			Expression: `has(resource.spec.persistentVolumeReclaimPolicy) && resource.spec.persistentVolumeReclaimPolicy == "Delete"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-073": {ResourceType: "storageclasses", Namespace: "",
			Expression: `!has(resource.allowVolumeExpansion) || resource.allowVolumeExpansion != true`, MatchPolicy: "any_match_fail"},

		// ===== 供应链与运行时 =====
		"CIS-K8S-074": {ResourceType: "pods", Namespace: "!system",
			Expression: `resource.spec.containers.exists(c, !c.image.contains("@sha256:"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-075": {ResourceType: "pods", Namespace: "!system",
			Expression: `has(resource.spec.initContainers) && resource.spec.initContainers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-076": {ResourceType: "pods", Namespace: "!system",
			Expression: `(!has(resource.spec.imagePullSecrets) || size(resource.spec.imagePullSecrets) == 0) && resource.spec.containers.exists(c, c.image.contains("/") && !c.image.startsWith("docker.io/") && !c.image.startsWith("registry.k8s.io/"))`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-077": {ResourceType: "pods", Namespace: "*",
			Expression: `has(resource.status) && has(resource.status.phase) && resource.status.phase == "Pending"`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-078": {ResourceType: "pods", Namespace: "*",
			Expression: `has(resource.status) && has(resource.status.containerStatuses) && resource.status.containerStatuses.exists(cs, cs.restartCount > 10)`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-079": {ResourceType: "pods", Namespace: "*",
			Expression: `has(resource.status) && has(resource.status.containerStatuses) && resource.status.containerStatuses.exists(cs, has(cs.state) && has(cs.state.waiting) && has(cs.state.waiting.reason) && cs.state.waiting.reason == "CrashLoopBackOff")`, MatchPolicy: "any_match_fail"},
		"CIS-K8S-080": {ResourceType: "pods", Namespace: "!system",
			Expression: `(!has(resource.metadata.ownerReferences) || size(resource.metadata.ownerReferences) == 0) && (!has(annotations["kubernetes.io/config.mirror"]))`, MatchPolicy: "any_match_fail"},
	}
}

// initKubeBaselineRules 初始化内置容器基线检查规则
// 增量导入：按 check_id 去重，已存在的跳过
func initKubeBaselineRules(db *gorm.DB, logger *zap.Logger) error {
	builtinRules := []model.KubeBaselineRule{
		// ===== RBAC 安全 =====
		{CheckID: "CIS-K8S-001", CheckName: "匿名用户 ClusterRoleBinding 检查", Category: "RBAC", Severity: "critical", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在绑定到 system:anonymous 或 system:unauthenticated 的 ClusterRoleBinding", Remediation: "删除绑定到匿名用户的 ClusterRoleBinding"},
		{CheckID: "CIS-K8S-005", CheckName: "默认 ServiceAccount 使用检查", Category: "RBAC", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否有 Pod 使用默认 ServiceAccount 且未禁用 token 自动挂载", Remediation: "为工作负载创建专用 ServiceAccount，设置 automountServiceAccountToken: false"},
		{CheckID: "CIS-K8S-006", CheckName: "cluster-admin ClusterRoleBinding 审计", Category: "RBAC", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查非必要的 cluster-admin ClusterRoleBinding 绑定", Remediation: "移除不必要的 cluster-admin 绑定，使用最小权限原则"},
		{CheckID: "CIS-K8S-007", CheckName: "通配符 RBAC 权限检查", Category: "RBAC", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 ClusterRole 中是否使用通配符 (*) 资源或动词", Remediation: "将通配符权限替换为具体的资源和动词列表"},
		{CheckID: "CIS-K8S-008", CheckName: "Pod exec/attach 权限检查", Category: "RBAC", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否有角色授予 pods/exec 或 pods/attach 权限", Remediation: "限制 pods/exec 和 pods/attach 权限，仅授予必要的管理员角色"},
		{CheckID: "CIS-K8S-009", CheckName: "Secrets 访问权限检查", Category: "RBAC", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否有角色授予 secrets 的 list/get/watch 权限", Remediation: "限制 secrets 访问权限，仅授予必要的服务账户"},
		{CheckID: "CIS-K8S-010", CheckName: "权限提升 RBAC 检查", Category: "RBAC", Severity: "critical", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否有角色授予 escalate 或 bind 权限", Remediation: "移除 escalate 和 bind 权限，防止权限提升"},
		{CheckID: "CIS-K8S-011", CheckName: "ServiceAccount 自动挂载 Token 检查", Category: "RBAC", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 ServiceAccount 是否启用了自动挂载 Token", Remediation: "在 ServiceAccount 上设置 automountServiceAccountToken: false"},
		{CheckID: "CIS-K8S-012", CheckName: "system:masters 绑定检查", Category: "RBAC", Severity: "critical", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否有自定义绑定到 system:masters 组", Remediation: "避免将用户或 ServiceAccount 绑定到 system:masters 组"},

		// ===== Pod 安全 =====
		{CheckID: "CIS-K8S-003", CheckName: "特权容器检查", Category: "Pod Security", Severity: "critical", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查集群中是否存在运行中的特权容器", Remediation: "移除容器的 privileged: true 配置，使用最小权限原则"},
		{CheckID: "CIS-K8S-004", CheckName: "hostNetwork/hostPID/hostIPC 检查", Category: "Pod Security", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在使用 hostNetwork、hostPID 或 hostIPC 的 Pod", Remediation: "移除 Pod 的 hostNetwork/hostPID/hostIPC 配置"},
		{CheckID: "CIS-K8S-013", CheckName: "以 Root 运行容器检查", Category: "Pod Security", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否以 root 用户运行（runAsNonRoot 未设置或 runAsUser=0）", Remediation: "设置 securityContext.runAsNonRoot: true 或 runAsUser 为非零值"},
		{CheckID: "CIS-K8S-014", CheckName: "危险 Capabilities 检查", Category: "Pod Security", Severity: "critical", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否拥有危险 Capabilities (NET_RAW, SYS_ADMIN, ALL)", Remediation: "移除危险 Capabilities，仅保留必要的最小权限"},
		{CheckID: "CIS-K8S-015", CheckName: "只读根文件系统检查", Category: "Pod Security", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否设置了只读根文件系统", Remediation: "设置 securityContext.readOnlyRootFilesystem: true"},
		{CheckID: "CIS-K8S-016", CheckName: "AllowPrivilegeEscalation 检查", Category: "Pod Security", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否允许权限提升", Remediation: "设置 securityContext.allowPrivilegeEscalation: false"},
		{CheckID: "CIS-K8S-017", CheckName: "hostPath 卷挂载检查", Category: "Pod Security", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Pod 是否挂载了 hostPath 卷", Remediation: "避免使用 hostPath 卷，改用 PersistentVolume 或 emptyDir"},
		{CheckID: "CIS-K8S-018", CheckName: "Docker Socket 挂载检查", Category: "Pod Security", Severity: "critical", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否挂载了 Docker Socket (/var/run/docker.sock)", Remediation: "移除 Docker Socket 挂载，避免容器逃逸风险"},
		{CheckID: "CIS-K8S-019", CheckName: "Seccomp Profile 检查", Category: "Pod Security", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Pod 是否配置了 Seccomp Profile", Remediation: "设置 securityContext.seccompProfile.type 为 RuntimeDefault 或 Localhost"},
		{CheckID: "CIS-K8S-020", CheckName: "CPU 资源限制检查", Category: "Pod Security", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否设置了 CPU 资源限制", Remediation: "为所有容器设置 resources.limits.cpu"},
		{CheckID: "CIS-K8S-021", CheckName: "内存资源限制检查", Category: "Pod Security", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否设置了内存资源限制", Remediation: "为所有容器设置 resources.limits.memory"},
		{CheckID: "CIS-K8S-022", CheckName: "资源请求检查", Category: "Pod Security", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否设置了资源请求 (requests)", Remediation: "为所有容器设置 resources.requests.cpu 和 resources.requests.memory"},
		{CheckID: "CIS-K8S-023", CheckName: "存活探针检查", Category: "Pod Security", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否配置了存活探针 (livenessProbe)", Remediation: "为长时间运行的容器配置 livenessProbe"},
		{CheckID: "CIS-K8S-024", CheckName: "就绪探针检查", Category: "Pod Security", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否配置了就绪探针 (readinessProbe)", Remediation: "为提供服务的容器配置 readinessProbe"},
		{CheckID: "CIS-K8S-025", CheckName: "镜像 :latest 标签检查", Category: "Pod Security", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否使用 :latest 标签或未指定标签的镜像", Remediation: "使用明确的版本标签替代 :latest"},
		{CheckID: "CIS-K8S-026", CheckName: "镜像拉取策略检查", Category: "Pod Security", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否设置了 imagePullPolicy: Always", Remediation: "设置 imagePullPolicy: Always 确保使用最新镜像"},
		{CheckID: "CIS-K8S-027", CheckName: "hostPort 使用检查", Category: "Pod Security", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否使用了 hostPort", Remediation: "避免使用 hostPort，改用 Service 暴露端口"},
		{CheckID: "CIS-K8S-028", CheckName: "额外 Capabilities 添加检查", Category: "Pod Security", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否添加了额外的 Linux Capabilities", Remediation: "移除不必要的 Capabilities，使用 drop ALL + 仅添加必需的方式"},

		// ===== 网络安全 =====
		{CheckID: "CIS-K8S-002", CheckName: "NetworkPolicy 覆盖率检查", Category: "Network", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查所有非系统 Namespace 是否配置了 NetworkPolicy", Remediation: "为所有业务 Namespace 配置 NetworkPolicy 限制网络访问"},
		{CheckID: "CIS-K8S-029", CheckName: "默认拒绝入站 NetworkPolicy 检查", Category: "Network", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查非系统 Namespace 是否配置了默认拒绝入站的 NetworkPolicy", Remediation: "为每个 Namespace 创建默认拒绝入站流量的 NetworkPolicy"},
		{CheckID: "CIS-K8S-030", CheckName: "默认拒绝出站 NetworkPolicy 检查", Category: "Network", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查非系统 Namespace 是否配置了默认拒绝出站的 NetworkPolicy", Remediation: "为每个 Namespace 创建默认拒绝出站流量的 NetworkPolicy"},
		{CheckID: "CIS-K8S-031", CheckName: "NodePort 类型 Service 检查", Category: "Network", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在 NodePort 类型的 Service", Remediation: "使用 ClusterIP + Ingress 替代 NodePort，减少攻击面"},
		{CheckID: "CIS-K8S-032", CheckName: "LoadBalancer 类型 Service 检查", Category: "Network", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "审计 LoadBalancer 类型的 Service（可能暴露到外网）", Remediation: "审查 LoadBalancer Service 是否必要，考虑使用 Ingress 替代"},
		{CheckID: "CIS-K8S-033", CheckName: "ExternalIPs Service 检查", Category: "Network", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在配置了 ExternalIPs 的 Service", Remediation: "移除 Service 的 externalIPs 配置，使用 LoadBalancer 或 Ingress 替代"},
		{CheckID: "CIS-K8S-034", CheckName: "Ingress TLS 配置检查", Category: "Network", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Ingress 资源是否配置了 TLS", Remediation: "为所有 Ingress 配置 TLS 证书，启用 HTTPS"},
		{CheckID: "CIS-K8S-035", CheckName: "无 Selector 的 Service 检查", Category: "Network", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在没有 selector 的 Service（可能指向外部端点）", Remediation: "确认无 selector 的 Service 是否必要，添加说明注解"},

		// ===== 密钥与配置 =====
		{CheckID: "CIS-K8S-036", CheckName: "环境变量中的 Secret 引用检查", Category: "Secrets & Config", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器是否通过环境变量引用 Secret（建议使用 volume 挂载）", Remediation: "使用 volume 挂载方式注入 Secret，而非环境变量"},
		{CheckID: "CIS-K8S-037", CheckName: "默认 Namespace 使用检查", Category: "Secrets & Config", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否有工作负载运行在 default Namespace", Remediation: "将工作负载部署到专用 Namespace，避免使用 default"},
		{CheckID: "CIS-K8S-038", CheckName: "Tiller (Helm v2) 检测", Category: "Secrets & Config", Severity: "critical", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查集群中是否存在已弃用的 Tiller (Helm v2) 组件", Remediation: "升级到 Helm v3，移除 Tiller 部署"},
		{CheckID: "CIS-K8S-039", CheckName: "大容量 Secret 检查", Category: "Secrets & Config", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Secret 大小是否超过 1MB（可能影响 etcd 性能）", Remediation: "拆分大型 Secret 或使用外部密钥管理系统"},
		{CheckID: "CIS-K8S-040", CheckName: "大容量 ConfigMap 检查", Category: "Secrets & Config", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 ConfigMap 大小是否超过 1MB", Remediation: "拆分大型 ConfigMap 或使用外部配置服务"},
		{CheckID: "CIS-K8S-041", CheckName: "Namespace 标签规范检查", Category: "Secrets & Config", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Namespace 是否缺少标准标签（如 team、environment）", Remediation: "为 Namespace 添加标准化标签以便管理和审计"},
		{CheckID: "CIS-K8S-042", CheckName: "ServiceAccount Secret 类型检查", Category: "Secrets & Config", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在遗留的 ServiceAccount Token Secret", Remediation: "使用 TokenRequest API 替代持久化 ServiceAccount Token"},
		{CheckID: "CIS-K8S-043", CheckName: "Pod 环境变量明文密码检查", Category: "Secrets & Config", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器环境变量中是否包含明文密码（通过关键字匹配）", Remediation: "使用 Secret 资源管理敏感信息，避免明文存储"},

		// ===== 工作负载安全 =====
		{CheckID: "CIS-K8S-044", CheckName: "单副本 Deployment 检查", Category: "Workload", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Deployment 是否只有单副本（影响可用性）", Remediation: "为生产 Deployment 设置至少 2 个副本"},
		{CheckID: "CIS-K8S-045", CheckName: "PodDisruptionBudget 覆盖检查", Category: "Workload", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Deployment 是否配置了 PodDisruptionBudget", Remediation: "为关键 Deployment 创建 PodDisruptionBudget"},
		{CheckID: "CIS-K8S-046", CheckName: "CronJob 无超时限制检查", Category: "Workload", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 CronJob 是否设置了 activeDeadlineSeconds", Remediation: "为 CronJob 设置 activeDeadlineSeconds 防止任务永不超时"},
		{CheckID: "CIS-K8S-047", CheckName: "不可信镜像仓库检查", Category: "Workload", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器镜像是否来自可信的镜像仓库", Remediation: "仅使用企业内部镜像仓库或白名单镜像仓库"},
		{CheckID: "CIS-K8S-048", CheckName: "HPA 最小副本数检查", Category: "Workload", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 HPA 的 minReplicas 是否大于 1", Remediation: "设置 HPA minReplicas >= 2 保证高可用"},
		{CheckID: "CIS-K8S-049", CheckName: "DaemonSet 资源限制检查", Category: "Workload", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 DaemonSet 容器是否设置了资源限制", Remediation: "为 DaemonSet 容器设置 CPU 和内存资源限制"},
		{CheckID: "CIS-K8S-050", CheckName: "Job 无重试限制检查", Category: "Workload", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Job 是否设置了 backoffLimit", Remediation: "为 Job 设置合理的 backoffLimit 防止无限重试"},
		{CheckID: "CIS-K8S-051", CheckName: "Deployment 更新策略检查", Category: "Workload", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Deployment 是否使用 RollingUpdate 策略", Remediation: "使用 RollingUpdate 策略确保零停机部署"},
		{CheckID: "CIS-K8S-052", CheckName: "StatefulSet 持久化存储检查", Category: "Workload", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 StatefulSet 是否配置了 volumeClaimTemplates", Remediation: "为 StatefulSet 配置持久化存储保证数据安全"},
		{CheckID: "CIS-K8S-053", CheckName: "Pod 反亲和性检查", Category: "Workload", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查多副本 Deployment 是否配置了 Pod 反亲和性", Remediation: "配置 podAntiAffinity 确保 Pod 分散在不同节点"},
		{CheckID: "CIS-K8S-054", CheckName: "Pod 拓扑分布约束检查", Category: "Workload", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查多副本 Deployment 是否配置了拓扑分布约束", Remediation: "配置 topologySpreadConstraints 确保跨区域分布"},
		{CheckID: "CIS-K8S-055", CheckName: "Deployment 自动扩展检查", Category: "Workload", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Deployment 是否配置了 HPA 自动扩展", Remediation: "为关键 Deployment 配置 HPA 以应对流量波动"},

		// ===== 节点安全 =====
		{CheckID: "CIS-K8S-056", CheckName: "节点 NotReady 状态检查", Category: "Node", Severity: "critical", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在 NotReady 状态的节点", Remediation: "排查 NotReady 节点的问题并恢复"},
		{CheckID: "CIS-K8S-057", CheckName: "节点压力条件检查", Category: "Node", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查节点是否存在内存/磁盘/PID 压力", Remediation: "扩容节点资源或迁移工作负载"},
		{CheckID: "CIS-K8S-058", CheckName: "节点内核版本检查", Category: "Node", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查节点内核版本是否过旧（< 4.19）", Remediation: "升级节点内核版本至 4.19+"},
		{CheckID: "CIS-K8S-059", CheckName: "节点容器运行时检查", Category: "Node", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查节点容器运行时类型和版本", Remediation: "使用推荐的容器运行时 (containerd/CRI-O)"},
		{CheckID: "CIS-K8S-060", CheckName: "节点资源分配率检查", Category: "Node", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查节点资源分配率是否超过 90%", Remediation: "增加节点或迁移工作负载以降低资源使用率"},
		{CheckID: "CIS-K8S-061", CheckName: "节点不可调度检查", Category: "Node", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在被标记为不可调度的节点", Remediation: "恢复节点可调度状态或增加新节点"},
		{CheckID: "CIS-K8S-062", CheckName: "节点 Taint 检查", Category: "Node", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查节点 Taint 配置是否合理", Remediation: "审查节点 Taint 配置，确保 NoSchedule/NoExecute 设置合理"},
		{CheckID: "CIS-K8S-063", CheckName: "孤儿 Pod 检查", Category: "Node", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在没有控制器管理的孤儿 Pod", Remediation: "使用 Deployment/StatefulSet/DaemonSet 管理 Pod"},
		{CheckID: "CIS-K8S-064", CheckName: "节点 Pod 数量检查", Category: "Node", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查节点上运行的 Pod 数量是否接近上限", Remediation: "增加节点或迁移 Pod 以降低密度"},

		// ===== 集群配置 =====
		{CheckID: "CIS-K8S-065", CheckName: "Kubernetes 版本检查", Category: "Cluster Config", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Kubernetes 版本是否在支持范围内", Remediation: "升级 Kubernetes 版本至受支持的版本"},
		{CheckID: "CIS-K8S-066", CheckName: "Namespace LimitRange 检查", Category: "Cluster Config", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查非系统 Namespace 是否配置了 LimitRange", Remediation: "为每个 Namespace 创建 LimitRange 限制资源使用"},
		{CheckID: "CIS-K8S-067", CheckName: "Namespace ResourceQuota 检查", Category: "Cluster Config", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查非系统 Namespace 是否配置了 ResourceQuota", Remediation: "为每个 Namespace 创建 ResourceQuota 限制资源总量"},
		{CheckID: "CIS-K8S-068", CheckName: "Pod Security Standards 标签检查", Category: "Cluster Config", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Namespace 是否配置了 Pod Security Standards (PSS) 标签", Remediation: "为 Namespace 设置 pod-security.kubernetes.io/enforce 标签"},
		{CheckID: "CIS-K8S-069", CheckName: "Admission Webhook 检查", Category: "Cluster Config", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否配置了 ValidatingWebhookConfiguration", Remediation: "配置准入 Webhook 加强安全策略执行"},
		{CheckID: "CIS-K8S-070", CheckName: "MutatingWebhook 超时检查", Category: "Cluster Config", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 MutatingWebhook 超时设置是否合理", Remediation: "设置 MutatingWebhook 超时为 10s 以下，避免阻塞 API"},
		{CheckID: "CIS-K8S-071", CheckName: "Namespace 数量审计", Category: "Cluster Config", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "审计集群中非系统 Namespace 的数量", Remediation: "清理不再使用的 Namespace"},
		{CheckID: "CIS-K8S-072", CheckName: "PersistentVolume 回收策略检查", Category: "Cluster Config", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 PersistentVolume 是否使用 Delete 回收策略", Remediation: "对重要数据使用 Retain 策略，防止数据丢失"},
		{CheckID: "CIS-K8S-073", CheckName: "StorageClass 扩展配置检查", Category: "Cluster Config", Severity: "low", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 StorageClass 是否启用了卷扩展", Remediation: "设置 StorageClass allowVolumeExpansion: true"},

		// ===== 供应链与运行时 =====
		{CheckID: "CIS-K8S-074", CheckName: "镜像无 Digest 检查", Category: "Supply Chain", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查容器镜像是否使用了 digest 引用", Remediation: "使用 image@sha256:digest 格式引用镜像，确保不可变性"},
		{CheckID: "CIS-K8S-075", CheckName: "Init 容器安全检查", Category: "Supply Chain", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Init 容器是否遵守安全最佳实践（非特权、非 root）", Remediation: "Init 容器也应遵循最小权限原则"},
		{CheckID: "CIS-K8S-076", CheckName: "imagePullSecrets 检查", Category: "Supply Chain", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查 Pod 是否配置了 imagePullSecrets（私有仓库）", Remediation: "为使用私有镜像仓库的 Pod 配置 imagePullSecrets"},
		{CheckID: "CIS-K8S-077", CheckName: "Pending 状态 Pod 检查", Category: "Runtime", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在长时间处于 Pending 状态的 Pod", Remediation: "排查 Pending Pod 的调度问题（资源不足、亲和性等）"},
		{CheckID: "CIS-K8S-078", CheckName: "高重启次数 Pod 检查", Category: "Runtime", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在重启次数超过 10 次的 Pod", Remediation: "排查 Pod 频繁重启的原因（OOM、健康检查失败等）"},
		{CheckID: "CIS-K8S-079", CheckName: "CrashLoopBackOff Pod 检查", Category: "Runtime", Severity: "high", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在 CrashLoopBackOff 状态的 Pod", Remediation: "查看 Pod 日志排查崩溃原因"},
		{CheckID: "CIS-K8S-080", CheckName: "无属主 Pod 检查", Category: "Runtime", Severity: "medium", Builtin: true, Enabled: true, Benchmark: cisBenchmarkVersion,
			Description: "检查是否存在没有 OwnerReference 的 Pod（不受控制器管理）", Remediation: "使用 Deployment/StatefulSet 等控制器管理 Pod"},
	}

	// 获取内置 CEL 检查配置
	configs := builtinCheckConfigs()

	// 查询已存在的 check_id
	var existingIDs []string
	db.Model(&model.KubeBaselineRule{}).Pluck("check_id", &existingIDs)
	idSet := make(map[string]struct{}, len(existingIDs))
	for _, id := range existingIDs {
		idSet[id] = struct{}{}
	}

	// 增量插入（新规则带 CheckConfig）
	imported := 0
	for i := range builtinRules {
		if _, exists := idSet[builtinRules[i].CheckID]; exists {
			continue
		}
		if cfg, ok := configs[builtinRules[i].CheckID]; ok {
			builtinRules[i].CheckConfig = cfg
		}
		if err := db.Create(&builtinRules[i]).Error; err != nil {
			logger.Warn("导入内置容器基线规则失败", zap.String("check_id", builtinRules[i].CheckID), zap.Error(err))
			continue
		}
		imported++
	}

	if imported > 0 {
		logger.Info("内置容器基线规则导入完成", zap.Int("new", imported), zap.Int("existing", len(existingIDs)))
	}

	// 回填已有规则的 CheckConfig（仅更新 builtin=true 且 check_config IS NULL 的记录）
	backfilled := 0
	for checkID, cfg := range configs {
		result := db.Model(&model.KubeBaselineRule{}).
			Where("check_id = ? AND builtin = ? AND check_config IS NULL", checkID, true).
			Update("check_config", cfg)
		if result.Error != nil {
			logger.Warn("回填基线规则 CheckConfig 失败", zap.String("check_id", checkID), zap.Error(result.Error))
			continue
		}
		if result.RowsAffected > 0 {
			backfilled++
		}
	}
	if backfilled > 0 {
		logger.Info("内置容器基线规则 CheckConfig 回填完成", zap.Int("backfilled", backfilled))
	}

	return nil
}

// initKubeExpressionTemplates 初始化内置 CEL 表达式模板
// 增量导入：按 name 去重，已存在的跳过
func initKubeExpressionTemplates(db *gorm.DB, logger *zap.Logger) error {
	builtinTemplates := []model.KubeExpressionTemplate{
		{Name: "特权容器检测", Description: "检测运行在特权模式的容器", ResourceType: "pods", Namespace: "!system", Builtin: true,
			Expression: `resource.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)`, MatchPolicy: "any_match_fail"},
		{Name: "NodePort 服务检测", Description: "检测使用 NodePort 类型的 Service", ResourceType: "services", Namespace: "!system", Builtin: true,
			Expression: `resource.spec.type == "NodePort"`, MatchPolicy: "any_match_fail"},
		{Name: "HostNetwork 容器检测", Description: "检测使用主机网络命名空间的 Pod", ResourceType: "pods", Namespace: "!system", Builtin: true,
			Expression: `has(resource.spec.hostNetwork) && resource.spec.hostNetwork == true`, MatchPolicy: "any_match_fail"},
		{Name: "无资源限制容器", Description: "检测未设置 CPU/内存 limits 的容器", ResourceType: "pods", Namespace: "!system", Builtin: true,
			Expression: `resource.spec.containers.exists(c, !has(c.resources) || !has(c.resources.limits))`, MatchPolicy: "any_match_fail"},
		{Name: "latest 镜像标签", Description: "检测使用 latest 标签或未指定标签的镜像", ResourceType: "pods", Namespace: "!system", Builtin: true,
			Expression: `resource.spec.containers.exists(c, c.image.endsWith(":latest") || !c.image.contains(":"))`, MatchPolicy: "any_match_fail"},
		{Name: "单副本 Deployment", Description: "检测副本数为 1 的 Deployment（缺乏高可用）", ResourceType: "deployments", Namespace: "!system", Builtin: true,
			Expression: `has(resource.spec.replicas) && resource.spec.replicas <= 1`, MatchPolicy: "any_match_fail"},
		{Name: "default 命名空间使用", Description: "检测在 default 命名空间运行的 Pod", ResourceType: "pods", Namespace: "*", Builtin: true,
			Expression: `resource.metadata.namespace == "default"`, MatchPolicy: "any_match_fail"},
		{Name: "root 用户运行", Description: "检测以 root 用户运行的容器", ResourceType: "pods", Namespace: "!system", Builtin: true,
			Expression: `resource.spec.containers.exists(c, !has(c.securityContext) || !has(c.securityContext.runAsNonRoot) || c.securityContext.runAsNonRoot != true)`, MatchPolicy: "any_match_fail"},
		{Name: "匿名 RBAC 绑定", Description: "检测绑定到匿名用户的 ClusterRoleBinding", ResourceType: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io", Builtin: true,
			Expression: `resource.subjects.exists(s, s.name == "system:anonymous" || s.name == "system:unauthenticated")`, MatchPolicy: "any_match_fail"},
		{Name: "命名空间缺少 NetworkPolicy", Description: "检测没有任何 NetworkPolicy 的命名空间", ResourceType: "networkpolicies", Namespace: "!system", Builtin: true,
			Expression: `true`, MatchPolicy: "no_match_fail"},
	}

	// 查询已存在的模板名称
	var existingNames []string
	db.Model(&model.KubeExpressionTemplate{}).Pluck("name", &existingNames)
	nameSet := make(map[string]struct{}, len(existingNames))
	for _, name := range existingNames {
		nameSet[name] = struct{}{}
	}

	imported := 0
	for _, tmpl := range builtinTemplates {
		if _, exists := nameSet[tmpl.Name]; exists {
			continue
		}
		if err := db.Create(&tmpl).Error; err != nil {
			logger.Warn("导入内置 CEL 表达式模板失败", zap.String("name", tmpl.Name), zap.Error(err))
			continue
		}
		imported++
	}

	if imported > 0 {
		logger.Info("内置 CEL 表达式模板导入完成", zap.Int("new", imported), zap.Int("existing", len(existingNames)))
	}
	return nil
}

// permissionMeta 内置权限元数据。code 与 model.AllPermissionCodes 一一对应。
// 启动时 seed 到 permissions 表，handler 拿出来给 UI 渲染权限选择面板。
var permissionMeta = []model.Permission{
	{Code: model.PermDashboard, Name: "安全概览", Module: "dashboard", Description: "查看安全态势仪表盘"},
	{Code: model.PermAssets, Name: "资产中心", Module: "assets", Description: "查看主机、容器、软件包等资产"},
	{Code: model.PermAlerts, Name: "告警中心", Module: "alerts", Description: "查看与处置安全告警"},
	{Code: model.PermBaseline, Name: "基线安全", Module: "baseline", Description: "主机/容器合规基线检查"},
	{Code: model.PermFIM, Name: "文件完整性", Module: "fim", Description: "文件完整性监控与变更告警"},
	{Code: model.PermVirus, Name: "病毒查杀", Module: "antivirus", Description: "病毒扫描任务与隔离区"},
	{Code: model.PermVuln, Name: "漏洞管理", Module: "vuln", Description: "CVE 漏洞扫描与修复"},
	{Code: model.PermKube, Name: "容器集群", Module: "kube", Description: "K8s 集群安全审计"},
	{Code: model.PermDetection, Name: "威胁检测", Module: "detection", Description: "EDR / 入侵检测规则"},
	{Code: model.PermMonitoring, Name: "系统监控", Module: "monitoring", Description: "主机指标、SLO、报警"},
	{Code: model.PermOperations, Name: "运维中心", Module: "operations", Description: "插件版本、Agent 升级、备份"},
	{Code: model.PermAuditLog, Name: "审计日志", Module: "audit_log", Description: "查看操作审计"},
	{Code: model.PermUserManage, Name: "用户管理", Module: "user_manage", Description: "用户、角色、RBAC"},
	{Code: model.PermSystemConfig, Name: "系统设置", Module: "system_config", Description: "全局配置与告警通道"},
}

// initRBACPermissions seed 内置权限码到 permissions 表（增量，不覆盖已有 Name/Description）。
// 同时确保 admin 角色拥有全部权限（user 角色默认只读，由用户在 UI 上配置）。
func initRBACPermissions(db *gorm.DB, logger *zap.Logger) error {
	if db == nil {
		return nil
	}
	for _, p := range permissionMeta {
		// 按 code 增量：已存在不动（用户可能改过 Name），只插不存在的
		var existing model.Permission
		err := db.Where("code = ?", p.Code).First(&existing).Error
		if err == gorm.ErrRecordNotFound {
			if createErr := db.Create(&p).Error; createErr != nil {
				logger.Warn("seed permission 失败", zap.String("code", string(p.Code)), zap.Error(createErr))
			}
		}
	}

	// 内置角色 seed：
	//   - admin（平台超管）：每次启动确保拥有全部权限码（增量补齐，不删旧）。
	//   - 其余内置角色（安全管理员/分析师/运维/审计员/只读用户）：仅首次 seed
	//     （该角色尚无任何 role_permissions 行时），之后尊重管理员在 UI 上的定制。
	for _, role := range model.BuiltinRoles {
		if role.Code == "admin" {
			for _, code := range role.Permissions {
				if err := db.Where("role_code = ? AND perm_code = ?", role.Code, string(code)).
					Attrs(model.RolePermission{RoleCode: role.Code, PermCode: string(code)}).
					FirstOrCreate(&model.RolePermission{}).Error; err != nil {
					logger.Warn("seed admin role_permission 失败", zap.String("perm", string(code)), zap.Error(err))
				}
			}
			continue
		}
		var existing int64
		db.Model(&model.RolePermission{}).Where("role_code = ?", role.Code).Count(&existing)
		if existing > 0 {
			continue // 已存在（含管理员定制），不覆盖
		}
		for _, code := range role.Permissions {
			rp := model.RolePermission{RoleCode: role.Code, PermCode: string(code)}
			if err := db.Create(&rp).Error; err != nil {
				logger.Warn("seed 内置角色权限失败", zap.String("role", role.Code), zap.String("perm", string(code)), zap.Error(err))
			}
		}
		logger.Info("内置角色已 seed", zap.String("role", role.Code), zap.String("name", role.Name), zap.Int("perms", len(role.Permissions)))
	}
	logger.Info("RBAC 权限元数据已初始化", zap.Int("permissions", len(permissionMeta)))
	return nil
}
