package biz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz/advisory"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	osvTimeout = 30 * time.Second
)

// VulnScanner 漏洞扫描器。
//
// 历史上直接调 osv.dev，v2.7 后 OSV 路径统一走 advisory.Coordinator.SyncByPURLs
// （详见 doScanAll / ScanIncremental），仅保留 NVD / RedHat / Exploit / Priority 等
// 增强同步与 SyncOnly cron 入口。
//
// httpClient 仍由 NVD/RedHat 等子 sync 复用（如 SyncNVDMetadataCounted）。
type VulnScanner struct {
	db           *gorm.DB
	httpClient   *http.Client
	logger       *zap.Logger
	cacheManager *VulnCacheManager
}

// NewVulnScanner 创建漏洞扫描器
func NewVulnScanner(db *gorm.DB, logger *zap.Logger) *VulnScanner {
	return &VulnScanner{
		db: db,
		httpClient: &http.Client{
			Timeout: osvTimeout,
		},
		logger:       logger,
		cacheManager: NewVulnCacheManager(db, logger),
	}
}

// purlInfo 软件包 PURL 信息
type purlInfo struct {
	PURL     string `gorm:"column:purl"`
	Name     string `gorm:"column:name"`
	Version  string `gorm:"column:version"`
	HostID   string `gorm:"column:host_id"`
	Hostname string `gorm:"column:hostname"`
	IP       string `gorm:"column:ip"`
	// Scope 来源标记：system | embedded | container
	// embedded 仅参与 PURL 维度匹配，不参与 CPE daemon 维度匹配（防 Go binary 内嵌依赖触发 daemon 误报）
	Scope string `gorm:"column:scope"`
}

// SyncOnly 仅同步漏洞数据库（NVD + Red Hat），不执行 OSV 主机扫描
func (v *VulnScanner) SyncOnly() error {
	startedAt := time.Now()

	record := model.SecurityDBSyncRecord{
		DBType:    "vuln-sync",
		Status:    "running",
		StartedAt: startedAt,
	}
	v.db.Create(&record)

	v.logger.Info("开始漏洞库同步（仅同步，不扫描主机）")

	// 逐个数据源同步，记录每个源的状态
	type sourceResult struct {
		Name   string `json:"name"`
		Status string `json:"status"` // success / failed / skipped
		Error  string `json:"error,omitempty"`
	}
	var results []sourceResult
	var coreErr error // 核心数据源失败

	// 核心数据源：用 advisory.Coordinator 统一调度 RHSA/Rocky/USN/Debian/OSV
	// 取代已 404 的 hydra REST NVD/RedHat sync，confidence=high 优先入库
	if err := v.syncCoreAdvisories(); err != nil {
		v.logger.Warn("advisory coordinator 同步失败", zap.Error(err))
		results = append(results, sourceResult{Name: "advisory-coordinator", Status: "failed", Error: err.Error()})
		if coreErr == nil {
			coreErr = err
		}
	} else {
		results = append(results, sourceResult{Name: "advisory-coordinator", Status: "success"})
	}

	// 增强数据源（失败不影响整体状态，按 cve_id 补全主表字段，不入独立 vuln）
	// 走 vuln_data_sources 表的 enabled 配置：disabled 跳过
	sourceSvc := NewVulnDataSourceService(v.db, v.logger)
	for _, src := range []struct {
		sourceName string // vuln_data_sources.name slug
		name       string
		fn         func() (int64, error)
	}{
		{"mitre-cve", "MITRECVE", v.SyncMITRECVECounted},    // MITRE 官方 CVE 元数据（推荐主源）
		{"nvd", "NVDMetadata", v.SyncNVDMetadataCounted},    // NVD API（备用，需 NVD_API_KEY 提速）
		{"cisa-kev", "CISAKev", v.SyncCISAKevCounted},       // CISA KEV 标记 in_kev
		{"exploit-db", "ExploitDB", v.SyncExploitDBCounted}, // exploit-db CSV 标记 has_exploit
		{"cnnvd", "CNNVD", wrapErr(v.SyncCNNVD)},            // 国家信息安全漏洞库（cnnvd.org.cn 官方 API，补 cnnvd_id）
		{"cnvd", "CNVD", wrapErr(v.SyncCNVDStub)},           // 国家信息安全漏洞共享平台（无公开 API / Cloudflare 521）
	} {
		if !sourceSvc.IsEnabled(src.sourceName) {
			v.logger.Debug("source disabled，跳过", zap.String("source", src.sourceName))
			results = append(results, sourceResult{Name: src.name, Status: "skipped"})
			continue
		}
		srcStart := time.Now()
		sourceSvc.MarkRunning(src.sourceName)
		count, err := src.fn()
		if err != nil {
			v.logger.Warn(src.name+" 同步失败，跳过", zap.Error(err))
			results = append(results, sourceResult{Name: src.name, Status: "failed", Error: err.Error()})
			sourceSvc.MarkFailed(src.sourceName, err)
		} else {
			results = append(results, sourceResult{Name: src.name, Status: "success"})
			sourceSvc.MarkSuccess(src.sourceName, count, time.Since(srcStart))
		}
	}

	// 重算漏洞优先级
	pc := NewPriorityCalculator(v.db, v.logger)
	if err := pc.RecalculateAll(); err != nil {
		v.logger.Warn("优先级重算失败", zap.Error(err))
	}

	// 写入同步结果
	duration := int(time.Since(startedAt).Seconds())
	updates := map[string]any{"duration": duration}
	resultsJSON, _ := json.Marshal(results)
	if coreErr != nil {
		updates["status"] = "failed"
	} else {
		updates["status"] = "success"
		updates["version"] = time.Now().Format("20060102.150405")
	}
	updates["error_msg"] = string(resultsJSON)
	v.db.Model(&record).Updates(updates)

	v.logger.Info("漏洞库同步完成", zap.Int("duration_seconds", duration))
	return coreErr
}

// GetLatestSyncStatus 查询最近一条漏洞相关同步记录
func (v *VulnScanner) GetLatestSyncStatus() (*model.SecurityDBSyncRecord, error) {
	var record model.SecurityDBSyncRecord
	err := v.db.Where("db_type IN ?", []string{"osv", "vuln-sync"}).Order("id DESC").First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &record, nil
}

// GetSyncHistory 分页查询漏洞相关同步历史记录
func (v *VulnScanner) GetSyncHistory(page, pageSize int) ([]model.SecurityDBSyncRecord, int64, error) {
	var total int64
	query := v.db.Model(&model.SecurityDBSyncRecord{}).Where("db_type IN ?", []string{"osv", "osv-incremental", "vuln-sync"})
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var records []model.SecurityDBSyncRecord
	offset := (page - 1) * pageSize
	err := query.Offset(offset).Limit(pageSize).Order("id DESC").Find(&records).Error
	return records, total, err
}

// ScanIncremental 增量漏洞扫描：仅扫描自上次扫描以来新增/变更的软件包
// 通过 software.collected_at > 上次扫描时间 筛选变更软件，大幅降低扫描耗时
func (v *VulnScanner) ScanIncremental() error {
	startedAt := time.Now()

	// 查询上次成功扫描的开始时间（osv 全量 或 osv-incremental 增量）
	var lastRecord model.SecurityDBSyncRecord
	var since time.Time
	err := v.db.Where("db_type IN ? AND status = ?", []string{"osv", "osv-incremental"}, "success").
		Order("started_at DESC").First(&lastRecord).Error
	if err != nil {
		// 无历史记录 → 回退到全量
		v.logger.Info("无增量基线记录，回退全量扫描")
		return v.ScanAll()
	}
	since = lastRecord.StartedAt

	// 插入 running 记录
	record := model.SecurityDBSyncRecord{
		DBType:    "osv-incremental",
		Status:    "running",
		StartedAt: startedAt,
	}
	v.db.Create(&record)

	v.logger.Info("开始增量漏洞扫描", zap.Time("since", since))

	packages, err := v.loadPURLPackagesSince(since)
	if err != nil {
		updates := map[string]any{"status": "failed", "error_msg": err.Error(), "duration": int(time.Since(startedAt).Seconds())}
		v.db.Model(&record).Updates(updates)
		return fmt.Errorf("查询增量软件包失败: %w", err)
	}

	if len(packages) == 0 {
		v.logger.Info("无新增/变更软件包，增量扫描跳过")
		duration := int(time.Since(startedAt).Seconds())
		v.db.Model(&record).Updates(map[string]any{
			"status":    "success",
			"version":   time.Now().Format("20060102.150405"),
			"error_msg": "无新增软件包，跳过",
			"duration":  duration,
		})
		return nil
	}

	v.logger.Info("增量软件包数", zap.Int("count", len(packages)))

	purls, purlInfoMap := buildPURLPkgInfo(packages)
	beforeFilter := len(purls)
	purls = advisory.FilterOSVPURLs(purls)
	v.logger.Info("增量 OSV 路径仅查询语言包生态 PURL",
		zap.Int("before_filter", beforeFilter),
		zap.Int("after_filter", len(purls)))

	knownVulnIDs := v.loadKnownVulnIDs()

	totalVulns := 0
	if len(purls) > 0 {
		coord := v.buildOSVCoordinator()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
		defer cancel()
		_, vulnCount, _, syncErr := coord.SyncByPURLs(ctx, "osv", purls, purlInfoMap, knownVulnIDs)
		if syncErr != nil {
			v.logger.Error("增量 OSV PURL sync 失败", zap.Error(syncErr))
		} else {
			totalVulns = vulnCount
		}
	}

	duration := int(time.Since(startedAt).Seconds())
	summary := fmt.Sprintf("增量扫描 %d 个 PURL，发现 %d 个漏洞", len(purls), totalVulns)

	v.logger.Info("增量漏洞扫描完成",
		zap.Int("total_purls", len(purls)),
		zap.Int("total_vulns", totalVulns),
		zap.Int("duration_seconds", duration))

	v.db.Model(&record).Updates(map[string]any{
		"status":    "success",
		"version":   time.Now().Format("20060102.150405"),
		"error_msg": summary,
		"duration":  duration,
	})
	return nil
}

// ScanAll 全量漏洞扫描：查询所有软件包 PURL → OSV.dev API → 写入漏洞表
func (v *VulnScanner) ScanAll() error {
	startedAt := time.Now()

	// 记录扫描前的漏洞数（用于计算新增数量）
	var beforeCount int64
	v.db.Model(&model.Vulnerability{}).Count(&beforeCount)

	// 插入 running 记录
	record := model.SecurityDBSyncRecord{
		DBType:    "osv",
		Status:    "running",
		StartedAt: startedAt,
	}
	v.db.Create(&record)

	v.logger.Info("开始全量漏洞扫描")

	err := v.doScanAll()
	duration := int(time.Since(startedAt).Seconds())

	updates := map[string]any{"duration": duration}
	if err != nil {
		updates["status"] = "failed"
		updates["error_msg"] = err.Error()
		v.db.Model(&record).Updates(updates)
		return err
	}

	// 生成扫描摘要
	var afterCount int64
	v.db.Model(&model.Vulnerability{}).Count(&afterCount)
	var criticalCount, highCount int64
	v.db.Model(&model.Vulnerability{}).Where("status = ? AND severity = ?", "unpatched", "critical").Count(&criticalCount)
	v.db.Model(&model.Vulnerability{}).Where("status = ? AND severity = ?", "unpatched", "high").Count(&highCount)
	var affectedHosts int64
	v.db.Model(&model.HostVulnerability{}).Where("status = ?", "unpatched").Distinct("host_id").Count(&affectedHosts)

	newVulns := afterCount - beforeCount
	summary := fmt.Sprintf("新增 %d 个漏洞，当前 Critical %d / High %d，影响 %d 台主机",
		newVulns, criticalCount, highCount, affectedHosts)

	updates["status"] = "success"
	updates["version"] = time.Now().Format("20060102.150405")
	updates["error_msg"] = summary // 非错误，记录扫描摘要

	v.logger.Info("全量漏洞扫描完成",
		zap.Int64("new_vulns", newVulns),
		zap.Int64("critical", criticalCount),
		zap.Int64("high", highCount),
		zap.Int64("affected_hosts", affectedHosts),
		zap.Int("duration_seconds", duration))

	v.db.Model(&record).Updates(updates)
	return nil
}

// doScanAll 实际执行扫描逻辑：走 advisory.Coordinator.SyncByPURLs 统一路径。
//
// 与旧 doScanAll 差异：
//   - 不再直接调 osv.dev /v1/querybatch，统一走 advisory.OSVSource
//   - vuln 字段（OsvID/PURL/AttackVector/VulnType/AffectedVersions）由 Coordinator 写
//   - 异步通报通过 WithVulnUpsertCallback 注入
//   - cacheManager 通过 osvDetailCacheAdapter 注入到 OSVSource
//
// 保留 NVD / RedHat / Exploit / PriorityCalculator 后处理（用 softwareByName 复用查询结果）。
func (v *VulnScanner) doScanAll() error {
	packages, err := v.loadAllPURLPackages()
	if err != nil {
		return fmt.Errorf("查询软件包 PURL 失败: %w", err)
	}
	if len(packages) == 0 {
		v.logger.Info("没有找到带 PURL 的软件包")
		return nil
	}
	v.logger.Info("查询到软件包", zap.Int("count", len(packages)))

	purls, purlInfoMap := buildPURLPkgInfo(packages)
	beforeFilter := len(purls)
	purls = advisory.FilterOSVPURLs(purls)
	v.logger.Info("OSV 路径仅查询语言包生态 PURL",
		zap.Int("before_filter", beforeFilter),
		zap.Int("after_filter", len(purls)))

	knownVulnIDs := v.loadKnownVulnIDs()
	v.logger.Info("增量优化：已加载现有漏洞标识", zap.Int("known_count", len(knownVulnIDs)))

	if len(purls) > 0 {
		coord := v.buildOSVCoordinator()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		purlCount, vulnCount, hostVulnCount, syncErr := coord.SyncByPURLs(ctx, "osv", purls, purlInfoMap, knownVulnIDs)
		if syncErr != nil {
			v.logger.Error("OSV PURL sync 失败", zap.Error(syncErr))
		} else {
			v.logger.Info("OSV PURL sync 完成",
				zap.Int("purl_processed", purlCount),
				zap.Int("vuln_upsert", vulnCount),
				zap.Int("host_vuln_links", hostVulnCount))
		}
	}

	// 构建 software name → 安装信息映射，供 NVD/RedHat 同步复用（避免重复查询 software 表）
	softwareByName := make(map[string][]installedSoftware)
	for _, pkg := range packages {
		key := strings.ToLower(pkg.Name)
		softwareByName[key] = append(softwareByName[key], installedSoftware{
			Name:     pkg.Name,
			Version:  pkg.Version,
			HostID:   pkg.HostID,
			Hostname: pkg.Hostname,
			IP:       pkg.IP,
		})
	}

	// NVD 补充同步：覆盖 OSV.dev 尚未收录的最新 CVE
	if err := v.SyncNVDWithSoftware(softwareByName); err != nil {
		v.logger.Warn("NVD 补充同步失败（不影响 OSV 数据）", zap.Error(err))
	}

	// Red Hat Security Data 补充同步
	if err := v.SyncRedHatWithSoftware(softwareByName); err != nil {
		v.logger.Warn("Red Hat 补充同步失败（不影响其他数据）", zap.Error(err))
	}

	// Exploit 利用标记同步
	if err := v.SyncExploit(); err != nil {
		v.logger.Warn("Exploit 标记同步失败（不影响其他数据）", zap.Error(err))
	}

	// 重算漏洞优先级
	pc := NewPriorityCalculator(v.db, v.logger)
	if err := pc.RecalculateAll(); err != nil {
		v.logger.Warn("优先级重算失败（不影响扫描结果）", zap.Error(err))
	}

	return nil
}

// loadAllPURLPackages 查所有带 PURL 的 software 行 + 主机 IP/hostname。
func (v *VulnScanner) loadAllPURLPackages() ([]purlInfo, error) {
	var packages []purlInfo
	err := v.db.Table("software AS s").
		Select("s.purl AS purl, s.name AS name, s.version AS version, s.host_id AS host_id, COALESCE(NULLIF(s.scope, ''), 'system') AS scope, COALESCE(h.hostname, '') AS hostname, COALESCE(JSON_UNQUOTE(JSON_EXTRACT(h.ipv4, '$[0]')), '') AS ip").
		Joins("LEFT JOIN hosts h ON h.host_id = s.host_id").
		Where("s.purl != '' AND s.purl IS NOT NULL").
		Scan(&packages).Error
	return packages, err
}

// loadPURLPackagesSince 仅查 collected_at > since 的 software 行（增量扫描用）。
func (v *VulnScanner) loadPURLPackagesSince(since time.Time) ([]purlInfo, error) {
	var packages []purlInfo
	err := v.db.Table("software AS s").
		Select("s.purl AS purl, s.name AS name, s.version AS version, s.host_id AS host_id, COALESCE(NULLIF(s.scope, ''), 'system') AS scope, COALESCE(h.hostname, '') AS hostname, COALESCE(JSON_UNQUOTE(JSON_EXTRACT(h.ipv4, '$[0]')), '') AS ip").
		Joins("LEFT JOIN hosts h ON h.host_id = s.host_id").
		Where("s.purl != '' AND s.purl IS NOT NULL AND s.collected_at > ?", since).
		Scan(&packages).Error
	return packages, err
}

// buildPURLPkgInfo 把 software 行去重成 PURL → PURLPkgInfo 映射，供 Coordinator.SyncByPURLs 用。
func buildPURLPkgInfo(packages []purlInfo) ([]string, map[string]advisory.PURLPkgInfo) {
	purlInfoMap := make(map[string]advisory.PURLPkgInfo)
	for _, pkg := range packages {
		info, ok := purlInfoMap[pkg.PURL]
		if !ok {
			info = advisory.PURLPkgInfo{
				PkgName:  pkg.Name,
				Version:  pkg.Version,
				Hostname: map[string]string{},
				IP:       map[string]string{},
			}
		}
		info.HostIDs = append(info.HostIDs, pkg.HostID)
		if pkg.Hostname != "" {
			info.Hostname[pkg.HostID] = pkg.Hostname
		}
		if pkg.IP != "" {
			info.IP[pkg.HostID] = pkg.IP
		}
		purlInfoMap[pkg.PURL] = info
	}
	purls := make([]string, 0, len(purlInfoMap))
	for p := range purlInfoMap {
		purls = append(purls, p)
	}
	return purls, purlInfoMap
}

// loadKnownVulnIDs 加载已入库 cve_id + osv_id 集合，FetchByPURLs 跳过它们的 detail HTTP。
func (v *VulnScanner) loadKnownVulnIDs() map[string]struct{} {
	known := make(map[string]struct{})
	var cveIDs []string
	v.db.Model(&model.Vulnerability{}).Pluck("cve_id", &cveIDs)
	for _, id := range cveIDs {
		if id != "" {
			known[id] = struct{}{}
		}
	}
	var osvIDs []string
	v.db.Model(&model.Vulnerability{}).Where("osv_id != ''").Pluck("DISTINCT osv_id", &osvIDs)
	for _, id := range osvIDs {
		if id != "" {
			known[id] = struct{}{}
		}
	}
	return known
}

// buildOSVCoordinator 构造已配置 OSV cache + bulletin callback 的 Coordinator。
//
// 当前仅 OSVSource 用 PURL 路径；其他 source 仍走 time-incremental Sync 路径（不受本方法影响）。
func (v *VulnScanner) buildOSVCoordinator() *advisory.Coordinator {
	coord := advisory.NewCoordinator(v.db, v.logger).
		WithEnabledChecker(NewVulnDataSourceService(v.db, v.logger)).
		WithVulnUpsertCallback(v.onVulnUpserted)

	if osvSrc := coord.FindPURLSource("osv"); osvSrc != nil {
		if osv, ok := osvSrc.(*advisory.OSVSource); ok {
			osv.WithCache(newOSVDetailCacheAdapter(v.cacheManager),
				osvCacheStrategy(v.cacheManager.GetMode()))
		}
	}
	return coord
}

// onVulnUpserted Coordinator.upsertVuln 成功后的钩子：异步创建 VulnBulletin + 发送通知。
//
// 必须自己 recover：advisory 子包不会 recover 这里的 panic。
func (v *VulnScanner) onVulnUpserted(vuln *model.Vulnerability, _ *advisory.Advisory) {
	if vuln == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				v.logger.Error("onVulnUpserted panic", zap.Any("recover", r))
			}
		}()
		bs := NewVulnBulletinService(v.db, v.logger)
		bulletin := bs.TryCreateBulletin(vuln)
		if bulletin == nil {
			return
		}
		ns := NewNotificationService(v.db, v.logger)
		if err := ns.SendVulnBulletinNotification(bulletin); err != nil {
			v.logger.Error("发送漏洞通报通知失败",
				zap.String("bulletin_no", bulletin.BulletinNo),
				zap.Error(err))
		}
	}()
}

// hostVulnEntry 主机漏洞关联条目（用于批量 upsert，redhat_sync 同 vuln_scanner 共用）。
type hostVulnEntry struct {
	HostID   string
	Hostname string
	IP       string
	Version  string
}

// upsertHostVulnsBatch 批量写 host_vulnerabilities，含已修复→重新打开逻辑。
//
// 与 advisory.Coordinator.upsertVuln 内部 host_vuln 写入路径不同，本方法供
// vuln_scanner 旧路径（redhat_sync 主机匹配）使用，保留以兼容存量 NVD/RedHat 同步。
func (v *VulnScanner) upsertHostVulnsBatch(vulnID uint, entries []hostVulnEntry) {
	if len(entries) == 0 {
		return
	}
	var vuln model.Vulnerability
	v.db.Select("fixed_version").First(&vuln, vulnID)

	const batchSize = 100
	for i := 0; i < len(entries); i += batchSize {
		end := i + batchSize
		if end > len(entries) {
			end = len(entries)
		}
		batch := entries[i:end]
		records := make([]model.HostVulnerability, 0, len(batch))
		for _, e := range batch {
			records = append(records, model.HostVulnerability{
				VulnID:         vulnID,
				HostID:         e.HostID,
				Hostname:       e.Hostname,
				IP:             e.IP,
				CurrentVersion: e.Version,
				Status:         "unpatched",
			})
		}
		v.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "vuln_id"}, {Name: "host_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"hostname", "ip", "current_version"}),
		}).Create(&records)

		if vuln.FixedVersion != "" {
			for _, e := range batch {
				if compareVersionStrings(e.Version, vuln.FixedVersion) < 0 {
					v.db.Model(&model.HostVulnerability{}).
						Where("vuln_id = ? AND host_id = ? AND status = ?", vulnID, e.HostID, "patched").
						Updates(map[string]any{
							"status":     "unpatched",
							"patched_at": nil,
						})
				}
			}
		}
	}

	var affectedCount int64
	v.db.Model(&model.HostVulnerability{}).
		Where("vuln_id = ? AND status = ?", vulnID, "unpatched").
		Count(&affectedCount)
	v.db.Model(&model.Vulnerability{}).Where("id = ?", vulnID).Update("affected_hosts", affectedCount)

	if affectedCount > 0 {
		v.db.Model(&model.Vulnerability{}).
			Where("id = ? AND status = ?", vulnID, "patched").
			Update("status", "unpatched")
	}
}

// pkgManagerFromType 由 software.package_type + host OS family 推 pkg manager 名。
// 用途：advisory.matcher 选 RPM vs dpkg vs apk 版本比较算法。
func pkgManagerFromType(pkgType, osFamily string) string {
	switch strings.ToLower(pkgType) {
	case "rpm":
		return "rpm"
	case "deb":
		return "dpkg"
	case "apk":
		return "apk"
	}
	switch strings.ToLower(osFamily) {
	case "ubuntu", "debian":
		return "dpkg"
	case "alpine":
		return "apk"
	}
	return "rpm"
}

// pkgTypeToEcosystem 将 software.package_type 映射到 advisory.Ecosystem 字符串。
// OS pkg 返回空 → matcher 走 OS gate；语言包返回对应生态名 → 走 ecosystem gate。
func pkgTypeToEcosystem(pkgType string) string {
	switch strings.ToLower(pkgType) {
	case "npm":
		return "npm"
	case "pypi", "python":
		return "PyPI"
	case "jar", "maven":
		return "Maven"
	case "go-module", "go-binary", "golang":
		return "Go"
	case "gem", "rubygems":
		return "RubyGems"
	case "cargo", "crates":
		return "crates.io"
	case "composer":
		return "Packagist"
	case "nuget":
		return "NuGet"
	case "pub":
		return "Pub"
	case "hex":
		return "Hex"
	}
	return ""
}

// parseCVSSv3Vector 解析 CVSS v3.x 向量字符串，返回 Base Score
func parseCVSSv3Vector(vector string) float64 {
	// 解析各指标
	metrics := make(map[string]string)
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	// Attack Vector
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	// Attack Complexity
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	// User Interaction
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	// Confidentiality, Integrity, Availability Impact
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	// Privileges Required (Scope Unchanged / Changed)
	prU := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prC := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}

	avVal, ok1 := av[metrics["AV"]]
	acVal, ok2 := ac[metrics["AC"]]
	uiVal, ok3 := ui[metrics["UI"]]
	cVal, ok4 := cia[metrics["C"]]
	iVal, ok5 := cia[metrics["I"]]
	aVal, ok6 := cia[metrics["A"]]
	scopeChanged := metrics["S"] == "C"

	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0
	}

	var prVal float64
	if scopeChanged {
		prVal = prC[metrics["PR"]]
	} else {
		prVal = prU[metrics["PR"]]
	}

	// ISS (Impact Sub Score)
	iss := 1 - (1-cVal)*(1-iVal)*(1-aVal)

	// Impact
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return 0
	}

	// Exploitability
	exploitability := 8.22 * avVal * acVal * prVal * uiVal

	// Base Score
	var base float64
	if scopeChanged {
		base = 1.08 * (impact + exploitability)
	} else {
		base = impact + exploitability
	}

	if base > 10.0 {
		base = 10.0
	}

	// Round up to nearest 0.1
	return roundUp(base)
}

// pow 简单幂运算
func pow(base float64, exp int) float64 {
	result := 1.0
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}

// roundUp 向上取整到 0.1
func roundUp(val float64) float64 {
	// 乘以 10，取 ceil，再除以 10
	scaled := val * 10
	truncated := float64(int(scaled))
	if scaled > truncated {
		return (truncated + 1) / 10
	}
	return truncated / 10
}

// syncCoreAdvisories 调用 advisory.Coordinator 拉取所有 OS Advisory + OSV 源。
// 替代已废弃的 hydra REST NVD/RedHat 实现，confidence=high/medium 严格匹配入库。
//
// hosts 取自 hosts 表（host_packages 软件清单后续 collector 上报后再 join 入参，
// 当前仅按 OS family + major 兼容性 match）。
func (v *VulnScanner) syncCoreAdvisories() error {
	// 必须 JOIN software 表带上每条主机的真实包清单，
	// 否则 advisory matcher.Match 因 host.PkgName="" 永远不匹配 → host_vuln 全部为空。
	// 历史 bug：原实现只查 hosts 表 OSFamily/OSMajor，advisory matcher 因 PkgName 空跳过所有 advisory，
	// 但旧版本通过别的路径误写入 host_vuln，导致 prod 出现 690k+ debian/alpine 错关联 RHEL 主机。
	// hosts 表无 ip 列（IP 在 network_interfaces JSON 内），advisory matcher 不依赖 IP，省略。
	type hostPkgRow struct {
		HostID      string
		Hostname    string
		OSFamily    string
		OSVersion   string
		Arch        string
		PkgName     string
		PkgVer      string
		PkgEpoch    string
		PkgRelease  string
		PkgArch     string
		PURL        string
		PackageType string
	}
	var rows []hostPkgRow
	if err := v.db.Table("hosts h").
		Select("h.host_id, h.hostname, h.os_family, h.os_version, h.arch, s.name as pkg_name, s.version as pkg_ver, s.epoch as pkg_epoch, s.release as pkg_release, s.architecture as pkg_arch, s.purl, s.package_type").
		Joins("JOIN software s ON s.host_id = h.host_id").
		Where("h.status = ?", "online").
		Find(&rows).Error; err != nil {
		return fmt.Errorf("加载 host+software 清单失败: %w", err)
	}
	hostsAdv := make([]advisory.HostSoftware, 0, len(rows))
	for _, r := range rows {
		hostsAdv = append(hostsAdv, advisory.HostSoftware{
			HostID:       r.HostID,
			Hostname:     r.Hostname,
			OSFamily:     r.OSFamily,
			OSVer:        r.OSVersion,
			OSMajor:      extractOSMajor(r.OSVersion),
			Arch:         r.Arch,
			PkgName:      r.PkgName,
			PkgVer:       r.PkgVer,
			PkgEpoch:     r.PkgEpoch,
			PkgVerRaw:    r.PkgVer, // 旧字段含完整 version，新数据下与 PkgVer 一致
			PkgRelease:   r.PkgRelease,
			PkgArch:      r.PkgArch,
			PURL:         r.PURL,
			PkgEcosystem: pkgTypeToEcosystem(r.PackageType),
			PkgManager:   pkgManagerFromType(r.PackageType, r.OSFamily),
		})
	}
	v.logger.Info("advisory coordinator 输入清单", zap.Int("host_pkg_rows", len(hostsAdv)))

	// 预查已入库 RHSA advisory ID，注入 RedHatSource skip 集合，
	// 避免每次 sync 重复拉取已知 advisory 的 CSAF detail（5w 条全量 HTTP 不可接受）。
	skipRHSA := v.loadKnownRHSAAdvisoryIDs()
	v.logger.Info("已入库 RHSA advisory 集合", zap.Int("count", len(skipRHSA)))

	rhsaSource := advisory.NewRedHatSource().
		WithSkipAdvisoryIDs(skipRHSA)
	sources := []advisory.Source{
		rhsaSource,
		advisory.NewRockySource(),
		advisory.NewUbuntuSource(),
		advisory.NewDebianSource(),
		advisory.NewOSVSource(),
		advisory.NewAlpineSource(),
		advisory.NewCentOSSource(),
	}

	coord := advisory.NewCoordinator(v.db, v.logger).
		WithSources(sources).
		WithEnabledChecker(NewVulnDataSourceService(v.db, v.logger))
	// 全量首跑 RHSA ~5w 条，并发 8 大约 30 min；为承载初次全量 + 富化耗时，timeout 2h。
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	vulnCount, hostVulnCount, err := coord.Sync(ctx, time.Time{}, hostsAdv)
	if err != nil {
		return fmt.Errorf("coordinator sync: %w", err)
	}
	v.logger.Info("advisory coordinator 同步完成",
		zap.Int("vuln_count", vulnCount),
		zap.Int("host_vuln_count", hostVulnCount),
		zap.Int("host_count", len(hostsAdv)),
	)
	return nil
}

// loadKnownRHSAAdvisoryIDs 从 vulnerabilities 表 source='rhsa' 记录的 reference_url
// 反向解析出 advisory ID 集合，用于 RedHatSource 跳过已入库 advisory 的 detail HTTP。
//
// reference_url 形如 "https://access.redhat.com/errata/RHSA-2024:1234"，
// 末段即 advisory ID。
func (v *VulnScanner) loadKnownRHSAAdvisoryIDs() map[string]struct{} {
	var urls []string
	v.db.Model(&model.Vulnerability{}).
		Where("source = ? AND reference_url != ''", "rhsa").
		Pluck("DISTINCT reference_url", &urls)
	out := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		if slash := strings.LastIndex(u, "/"); slash >= 0 && slash < len(u)-1 {
			id := u[slash+1:]
			if strings.HasPrefix(strings.ToUpper(id), "RHSA-") {
				out[id] = struct{}{}
			}
		}
	}
	return out
}

// wrapErr 把 func() error 适配成 func() (int64, error)（stub 没有 count）。
func wrapErr(fn func() error) func() (int64, error) {
	return func() (int64, error) {
		return 0, fn()
	}
}

func extractOSMajor(ver string) string {
	for i, c := range ver {
		if c == '.' {
			return ver[:i]
		}
	}
	return ver
}
