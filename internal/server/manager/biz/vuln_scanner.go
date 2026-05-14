package biz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	osvBatchURL          = "https://api.osv.dev/v1/querybatch"
	osvVulnURL           = "https://api.osv.dev/v1/vulns/"
	osvBatchSize         = 1000 // OSV.dev 单次最多 1000 个查询
	osvDetailConcurrency = 50   // 并发获取漏洞详情的最大协程数
	osvTimeout           = 30 * time.Second
)

// VulnScanner 漏洞扫描器，基于 OSV.dev API
type VulnScanner struct {
	db         *gorm.DB
	httpClient *http.Client
	logger     *zap.Logger
}

// NewVulnScanner 创建漏洞扫描器
func NewVulnScanner(db *gorm.DB, logger *zap.Logger) *VulnScanner {
	return &VulnScanner{
		db: db,
		httpClient: &http.Client{
			Timeout: osvTimeout,
		},
		logger: logger,
	}
}

// osvQueryBatchRequest OSV.dev 批量查询请求
type osvQueryBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	PURL string `json:"purl"`
}

// osvQueryBatchResponse OSV.dev 批量查询响应
type osvQueryBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVuln `json:"vulns,omitempty"`
}

type osvVuln struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Aliases    []string       `json:"aliases"`
	Upstream   []string       `json:"upstream"`
	Severity   []osvSeverity  `json:"severity,omitempty"`
	Affected   []osvAffected  `json:"affected,omitempty"`
	References []osvReference `json:"references,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced,omitempty"`
			Fixed      string `json:"fixed,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// purlInfo 软件包 PURL 信息
type purlInfo struct {
	PURL     string `gorm:"column:purl"`
	Name     string `gorm:"column:name"`
	Version  string `gorm:"column:version"`
	HostID   string `gorm:"column:host_id"`
	Hostname string `gorm:"column:hostname"`
	IP       string `gorm:"column:ip"`
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

	var lastErr error
	// NVD 同步
	if err := v.SyncNVD(); err != nil {
		v.logger.Warn("NVD 同步失败", zap.Error(err))
		lastErr = err
	}
	// Red Hat Security Data 同步
	if err := v.SyncRedHat(); err != nil {
		v.logger.Warn("Red Hat 同步失败", zap.Error(err))
		if lastErr == nil {
			lastErr = err
		}
	}

	duration := int(time.Since(startedAt).Seconds())
	updates := map[string]interface{}{"duration": duration}
	if lastErr != nil {
		updates["status"] = "failed"
		updates["error_msg"] = lastErr.Error()
	} else {
		updates["status"] = "success"
		updates["version"] = time.Now().Format("20060102.150405")
	}
	v.db.Model(&record).Updates(updates)

	v.logger.Info("漏洞库同步完成", zap.Int("duration_seconds", duration))
	return lastErr
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
	query := v.db.Model(&model.SecurityDBSyncRecord{}).Where("db_type IN ?", []string{"osv", "vuln-sync"})
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var records []model.SecurityDBSyncRecord
	offset := (page - 1) * pageSize
	err := query.Offset(offset).Limit(pageSize).Order("id DESC").Find(&records).Error
	return records, total, err
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
	updates["version"] = fmt.Sprintf("%s | %s", time.Now().Format("20060102.150405"), summary)

	v.logger.Info("全量漏洞扫描完成",
		zap.Int64("new_vulns", newVulns),
		zap.Int64("critical", criticalCount),
		zap.Int64("high", highCount),
		zap.Int64("affected_hosts", affectedHosts),
		zap.Int("duration_seconds", duration))

	v.db.Model(&record).Updates(updates)
	return nil
}

// doScanAll 实际执行扫描逻辑
func (v *VulnScanner) doScanAll() error {
	// 1. 查询所有有 PURL 的软件包（JOIN hosts 带上 hostname / ip 用于填充 host_vulnerabilities）
	var packages []purlInfo
	if err := v.db.Table("software AS s").
		Select("s.purl AS purl, s.name AS name, s.version AS version, s.host_id AS host_id, COALESCE(h.hostname, '') AS hostname, COALESCE(JSON_UNQUOTE(JSON_EXTRACT(h.ipv4, '$[0]')), '') AS ip").
		Joins("LEFT JOIN hosts h ON h.host_id = s.host_id").
		Where("s.purl != '' AND s.purl IS NOT NULL").
		Scan(&packages).Error; err != nil {
		return fmt.Errorf("查询软件包 PURL 失败: %w", err)
	}

	if len(packages) == 0 {
		v.logger.Info("没有找到带 PURL 的软件包")
		return nil
	}

	v.logger.Info("查询到软件包", zap.Int("count", len(packages)))

	// 2. 按 PURL 去重，记录每个 PURL 对应的主机列表 + 主机名映射
	purlHosts := make(map[string][]string)   // purl → []hostID
	purlPkgInfo := make(map[string]purlInfo) // purl → 包信息
	hostnameMap := make(map[string]string)   // hostID → hostname
	ipMap := make(map[string]string)         // hostID → ip
	for _, pkg := range packages {
		purlHosts[pkg.PURL] = append(purlHosts[pkg.PURL], pkg.HostID)
		if _, exists := purlPkgInfo[pkg.PURL]; !exists {
			purlPkgInfo[pkg.PURL] = pkg
		}
		if pkg.Hostname != "" {
			hostnameMap[pkg.HostID] = pkg.Hostname
		}
		if pkg.IP != "" {
			ipMap[pkg.HostID] = pkg.IP
		}
	}

	// 3. 构建去重后的 PURL 列表
	uniquePURLs := make([]string, 0, len(purlHosts))
	for purl := range purlHosts {
		uniquePURLs = append(uniquePURLs, purl)
	}

	v.logger.Info("去重后 PURL 数", zap.Int("count", len(uniquePURLs)))

	// 4. 预加载已有漏洞标识，用于增量优化（跳过已知漏洞的 API 调用）
	knownVulnIDs := make(map[string]struct{})
	var cveIDs []string
	v.db.Model(&model.Vulnerability{}).Pluck("cve_id", &cveIDs)
	for _, id := range cveIDs {
		knownVulnIDs[id] = struct{}{}
	}
	var osvIDs []string
	v.db.Model(&model.Vulnerability{}).Where("osv_id != ''").Pluck("DISTINCT osv_id", &osvIDs)
	for _, id := range osvIDs {
		knownVulnIDs[id] = struct{}{}
	}

	// 跨批次共享的漏洞详情缓存，避免同一漏洞在不同批次中重复获取
	detailCache := make(map[string]*osvVuln)

	v.logger.Info("增量优化：已加载现有漏洞标识", zap.Int("known_count", len(knownVulnIDs)))

	// 5. 分批调用 OSV.dev API
	totalVulns := 0
	for i := 0; i < len(uniquePURLs); i += osvBatchSize {
		end := i + osvBatchSize
		if end > len(uniquePURLs) {
			end = len(uniquePURLs)
		}
		batch := uniquePURLs[i:end]

		vulnCount, err := v.queryBatch(batch, purlHosts, purlPkgInfo, hostnameMap, ipMap, detailCache, knownVulnIDs)
		if err != nil {
			v.logger.Error("OSV.dev 批量查询失败",
				zap.Int("batch_start", i),
				zap.Error(err))
			continue
		}
		totalVulns += vulnCount
	}

	v.logger.Info("全量漏洞扫描完成",
		zap.Int("total_purls", len(uniquePURLs)),
		zap.Int("total_vulns", totalVulns))

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

	return nil
}

// queryBatch 批量查询 OSV.dev 并写入数据库
func (v *VulnScanner) queryBatch(purls []string, purlHosts map[string][]string, purlPkgInfo map[string]purlInfo, hostnameMap map[string]string, ipMap map[string]string, detailCache map[string]*osvVuln, knownVulnIDs map[string]struct{}) (int, error) {
	// 构建请求
	req := osvQueryBatchRequest{
		Queries: make([]osvQuery, len(purls)),
	}
	for i, purl := range purls {
		req.Queries[i] = osvQuery{Package: osvPackage{PURL: purl}}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("序列化请求失败: %w", err)
	}

	// 调用 API
	resp, err := v.httpClient.Post(osvBatchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("调用 OSV.dev API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("OSV.dev API 返回 %d: %s", resp.StatusCode, string(respBody))
	}

	var result osvQueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("解析 OSV.dev 响应失败: %w", err)
	}

	// 收集所有唯一漏洞 ID（querybatch 仅返回 id + modified）
	vulnIDSet := make(map[string]struct{})
	for _, qr := range result.Results {
		for _, item := range qr.Vulns {
			vulnIDSet[item.ID] = struct{}{}
		}
	}

	// 增量优化：分离新漏洞和已知漏洞
	var newIDs []string
	var existingIDs []string
	for id := range vulnIDSet {
		if _, inCache := detailCache[id]; inCache {
			continue // 已在跨批次缓存中
		}
		if _, known := knownVulnIDs[id]; known {
			existingIDs = append(existingIDs, id)
		} else {
			newIDs = append(newIDs, id)
		}
	}

	v.logger.Info("漏洞处理策略",
		zap.Int("total_unique", len(vulnIDSet)),
		zap.Int("existing_skip_api", len(existingIDs)),
		zap.Int("need_fetch", len(newIDs)),
	)

	// 仅为新漏洞获取完整详情
	if len(newIDs) > 0 {
		newDetails := v.fetchVulnDetailsBatch(newIDs)
		for id, detail := range newDetails {
			detailCache[id] = detail
			// 标记为已知，后续批次不再获取
			knownVulnIDs[id] = struct{}{}
		}
	}

	// 批量加载已知漏洞的 DB 记录（用于更新主机关联）
	existingRecordsByID := make(map[string][]uint) // osvID/cveID → [vuln_record_id, ...]
	if len(existingIDs) > 0 {
		var records []struct {
			ID    uint   `gorm:"column:id"`
			OsvID string `gorm:"column:osv_id"`
			CveID string `gorm:"column:cve_id"`
		}
		v.db.Model(&model.Vulnerability{}).
			Where("osv_id IN ? OR cve_id IN ?", existingIDs, existingIDs).
			Select("id, osv_id, cve_id").
			Find(&records)
		for _, r := range records {
			if r.OsvID != "" {
				existingRecordsByID[r.OsvID] = append(existingRecordsByID[r.OsvID], r.ID)
			}
			existingRecordsByID[r.CveID] = append(existingRecordsByID[r.CveID], r.ID)
		}
	}

	// 处理结果
	vulnCount := 0
	for i, qr := range result.Results {
		if i >= len(purls) {
			break
		}
		purl := purls[i]
		pkgInfo := purlPkgInfo[purl]

		for _, minVuln := range qr.Vulns {
			// 路径 1：新漏洞（有完整详情），创建漏洞记录 + 主机关联
			if fullVuln, ok := detailCache[minVuln.ID]; ok {
				cveIDs := v.extractCVEs(*fullVuln)
				severity := v.mapSeverity(*fullVuln)
				cvssScore := v.extractCVSS(*fullVuln)
				fixedVersion := v.extractFixedVersion(*fullVuln)
				referenceURL := v.extractReferenceURL(*fullVuln)

				for _, cveID := range cveIDs {
					vulnRecord := &model.Vulnerability{
						CveID:          cveID,
						OsvID:          fullVuln.ID,
						PURL:           purl,
						Severity:       severity,
						CvssScore:      cvssScore,
						Component:      pkgInfo.Name,
						Description:    fullVuln.Summary,
						Status:         "unpatched",
						DiscoveredAt:   model.LocalTime(time.Now()),
						CurrentVersion: pkgInfo.Version,
						FixedVersion:   fixedVersion,
						ReferenceUrl:   referenceURL,
					}

					if err := v.db.Clauses(clause.OnConflict{
						Columns:   []clause.Column{{Name: "cve_id"}},
						DoUpdates: clause.AssignmentColumns([]string{"osv_id", "purl", "cvss_score", "description", "fixed_version", "reference_url"}),
					}).Create(vulnRecord).Error; err != nil {
						v.logger.Error("写入漏洞记录失败", zap.String("cve_id", cveID), zap.Error(err))
						continue
					}
					if vulnRecord.ID == 0 {
						v.db.Where("cve_id = ?", cveID).Select("id").First(vulnRecord)
					}
					if vulnRecord.ID == 0 {
						continue
					}

					v.upsertHostVulns(vulnRecord.ID, purl, pkgInfo.Version, purlHosts, hostnameMap, ipMap)

					// 异步发送漏洞告警通知
					if len(purlHosts[purl]) > 0 {
						firstHost := purlHosts[purl][0]
						go func(vuln *model.Vulnerability, hostID, hostname string) {
							var host model.Host
							ip := ""
							if v.db.Select("ipv4").First(&host, "host_id = ?", hostID).Error == nil && len(host.IPv4) > 0 {
								ip = host.IPv4[0]
							}
							var affected int64
							v.db.Model(&model.HostVulnerability{}).Where("vuln_id = ? AND status = ?", vuln.ID, "unpatched").Count(&affected)
							ns := NewNotificationService(v.db, v.logger)
							if err := ns.SendVulnerabilityAlertNotification(&VulnerabilityAlertData{
								HostID: hostID, Hostname: hostname, IP: ip,
								CveID: vuln.CveID, Severity: vuln.Severity, CvssScore: vuln.CvssScore,
								Component: vuln.Component, CurrentVersion: vuln.CurrentVersion,
								FixedVersion: vuln.FixedVersion, Description: vuln.Description,
								AffectedHosts: int(affected),
							}); err != nil {
								v.logger.Error("发送漏洞告警通知失败", zap.String("cve_id", vuln.CveID), zap.Error(err))
							}
						}(vulnRecord, firstHost, hostnameMap[firstHost])
					}
					vulnCount++
				}
				continue
			}

			// 路径 2：已知漏洞，仅更新主机关联（不调 OSV API）
			if vulnIDs, ok := existingRecordsByID[minVuln.ID]; ok {
				for _, vulnID := range vulnIDs {
					v.upsertHostVulns(vulnID, purl, pkgInfo.Version, purlHosts, hostnameMap, ipMap)
				}
				vulnCount++
			}
		}
	}

	return vulnCount, nil
}

// hostVulnEntry 主机漏洞关联条目（用于批量 upsert）
type hostVulnEntry struct {
	HostID   string
	Hostname string
	IP       string
	Version  string
}

// upsertHostVulns 更新漏洞的主机关联和受影响主机数
func (v *VulnScanner) upsertHostVulns(vulnID uint, purl, version string, purlHosts map[string][]string, hostnameMap, ipMap map[string]string) {
	entries := make([]hostVulnEntry, 0)
	hostSeen := make(map[string]struct{})
	for _, hostID := range purlHosts[purl] {
		if _, exists := hostSeen[hostID]; exists {
			continue
		}
		hostSeen[hostID] = struct{}{}
		entries = append(entries, hostVulnEntry{
			HostID:   hostID,
			Hostname: hostnameMap[hostID],
			IP:       ipMap[hostID],
			Version:  version,
		})
	}
	v.upsertHostVulnsBatch(vulnID, entries)
}

// upsertHostVulnsBatch 批量更新主机-漏洞关联
// 处理已修复漏洞在新扫描中重新出现的场景：如果主机版本仍然是旧版本，重新标记为 unpatched
func (v *VulnScanner) upsertHostVulnsBatch(vulnID uint, entries []hostVulnEntry) {
	if len(entries) == 0 {
		return
	}

	// 查询该漏洞的修复版本（用于判断是否需要重新打开已修复的关联）
	var vuln model.Vulnerability
	v.db.Select("fixed_version").First(&vuln, vulnID)

	// 批量写入（每 100 条一批）
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

		// 处理已修复漏洞重新出现：当前版本仍低于修复版本时，重新标记为 unpatched
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

	// 更新受影响主机数
	var affectedCount int64
	v.db.Model(&model.HostVulnerability{}).
		Where("vuln_id = ? AND status = ?", vulnID, "unpatched").
		Count(&affectedCount)
	v.db.Model(&model.Vulnerability{}).Where("id = ?", vulnID).Update("affected_hosts", affectedCount)

	// 如果漏洞之前被标记为 patched 但现在又有 unpatched 主机，重新标记漏洞
	if affectedCount > 0 {
		v.db.Model(&model.Vulnerability{}).
			Where("id = ? AND status = ?", vulnID, "patched").
			Update("status", "unpatched")
	}
}

// fetchVulnDetail 获取单个漏洞的完整详情（querybatch 仅返回 id + modified）
func (v *VulnScanner) fetchVulnDetail(id string) (*osvVuln, error) {
	resp, err := v.httpClient.Get(osvVulnURL + id)
	if err != nil {
		return nil, fmt.Errorf("调用 OSV.dev 详情 API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV.dev 详情 API 返回 %d: %s", resp.StatusCode, string(respBody))
	}

	var vuln osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("解析漏洞详情失败: %w", err)
	}
	return &vuln, nil
}

// fetchVulnDetailsBatch 并发获取多个漏洞的完整详情
func (v *VulnScanner) fetchVulnDetailsBatch(ids []string) map[string]*osvVuln {
	results := make(map[string]*osvVuln)
	if len(ids) == 0 {
		return results
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, osvDetailConcurrency)

	for _, id := range ids {
		wg.Add(1)
		go func(vulnID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			detail, err := v.fetchVulnDetail(vulnID)
			if err != nil {
				v.logger.Warn("获取漏洞详情失败，跳过",
					zap.String("id", vulnID),
					zap.Error(err))
				return
			}

			mu.Lock()
			results[vulnID] = detail
			mu.Unlock()
		}(id)
	}

	wg.Wait()
	v.logger.Info("漏洞详情获取完成",
		zap.Int("requested", len(ids)),
		zap.Int("succeeded", len(results)))
	return results
}

// extractCVEs 从 OSV 漏洞中提取所有关联的 CVE ID
// 一个 RHSA 可能关联多个 CVE（如 RHSA-2023:5539 → CVE-2023-44488, CVE-2023-5217）
func (v *VulnScanner) extractCVEs(vuln osvVuln) []string {
	// ID 本身就是 CVE
	if strings.HasPrefix(vuln.ID, "CVE-") {
		return []string{vuln.ID}
	}

	seen := make(map[string]struct{})
	var cves []string

	// 检查 aliases
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			if _, ok := seen[alias]; !ok {
				seen[alias] = struct{}{}
				cves = append(cves, alias)
			}
		}
	}
	// 检查 upstream（Red Hat 生态的 CVE 关联在此字段）
	for _, up := range vuln.Upstream {
		if strings.HasPrefix(up, "CVE-") {
			if _, ok := seen[up]; !ok {
				seen[up] = struct{}{}
				cves = append(cves, up)
			}
		}
	}

	if len(cves) > 0 {
		return cves
	}
	// 没有 CVE ID，使用 OSV ID 作为回退
	return []string{vuln.ID}
}

// mapSeverity 映射严重级别
func (v *VulnScanner) mapSeverity(vuln osvVuln) string {
	cvss := v.extractCVSS(vuln)
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	case cvss > 0:
		return "low"
	default:
		return "medium"
	}
}

// extractCVSS 从 CVSS v3.x 向量字符串计算基础分数
// 向量格式: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
func (v *VulnScanner) extractCVSS(vuln osvVuln) float64 {
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" {
			score := parseCVSSv3Vector(sev.Score)
			if score > 0 {
				return score
			}
		}
	}
	return 0
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

// extractFixedVersion 提取修复版本
func (v *VulnScanner) extractFixedVersion(vuln osvVuln) string {
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}

// extractReferenceURL 提取参考链接
func (v *VulnScanner) extractReferenceURL(vuln osvVuln) string {
	for _, ref := range vuln.References {
		if ref.Type == "ADVISORY" || ref.Type == "WEB" {
			return ref.URL
		}
	}
	if len(vuln.References) > 0 {
		return vuln.References[0].URL
	}
	return ""
}
