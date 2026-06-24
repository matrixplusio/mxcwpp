package advisory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// EnabledChecker 判断 source 是否启用 + 写回同步状态 + 管理增量 watermark。
// 由 biz.VulnDataSourceService 实现，coordinator 通过接口注入解耦。
type EnabledChecker interface {
	IsEnabled(name string) bool
	MarkRunning(name string)
	MarkSuccess(name string, count int64, duration time.Duration)
	MarkFailed(name string, err error)

	// GetWatermark 取该 source 的上次成功 advisory.IssuedAt 最大值。
	// 零值表示首次 sync（全量拉）。
	GetWatermark(name string) time.Time
	// SetWatermark 推进 watermark（仅当 t 比当前更新）。失败 sync 不动 watermark。
	SetWatermark(name string, t time.Time)
}

// Coordinator 协调多个 Source 与 Matcher，合并去重写入 DB。
//
// 优先级：相同 CVE × host 由不同 source 重复出现时，confidence 高者覆盖低者。
//
//	high (OS Advisory) > medium (OSV) > low (NVD CPE)
//
// 入库前严格校验：
//   - PkgFix.Name 非空
//   - PkgFix.FixedVersion 非空
//   - 至少一个 CVE ID
//   - description 不含 "Windows" 关键字（防 OS-mismatch 漏网）
type Coordinator struct {
	db      *gorm.DB
	logger  *zap.Logger
	sources []Source
	matcher Matcher
	checker EnabledChecker // 可选：注入 enabled 检查与状态回写

	// onVulnUpserted 可选回调：upsertVuln 成功后调用。
	// 用途：异步创建 VulnBulletin、发送通知等。callback 必须自己 recover panic。
	onVulnUpserted func(vuln *model.Vulnerability, adv *Advisory)
}

// VulnUpsertCallback upsertVuln 成功后的回调签名。
type VulnUpsertCallback func(vuln *model.Vulnerability, adv *Advisory)

// NewCoordinator 构造默认 Coordinator，注册全部 5 个 source + DefaultMatcher。
func NewCoordinator(db *gorm.DB, logger *zap.Logger) *Coordinator {
	return &Coordinator{
		db:     db,
		logger: logger,
		sources: []Source{
			NewRedHatSource(),
			NewRockySource(),
			NewUbuntuSource(),
			NewDebianSource(),
			NewOSVSource(),
			NewAlpineSource(),
			NewCentOSSource(),
			// 信创 OS（当前 stub，待对接 P3-1a-2/P3-1b-2/P3-1c-2）
			NewOpenEulerSource(),
			NewAnolisSource(),
			NewKylinSource(),
			NewUOSSource(),
		},
		matcher: &DefaultMatcher{},
	}
}

// WithSources 测试用：替换 source 列表（注入 mock）。
func (c *Coordinator) WithSources(s []Source) *Coordinator {
	c.sources = s
	return c
}

// WithMatcher 测试用：替换 matcher。
func (c *Coordinator) WithMatcher(m Matcher) *Coordinator {
	c.matcher = m
	return c
}

// WithEnabledChecker 注入 enabled 检查器（生产用 biz.VulnDataSourceService）。
func (c *Coordinator) WithEnabledChecker(ck EnabledChecker) *Coordinator {
	c.checker = ck
	return c
}

// WithVulnUpsertCallback 注入 upsertVuln 成功回调（异步 bulletin / 通知钩子）。
func (c *Coordinator) WithVulnUpsertCallback(cb VulnUpsertCallback) *Coordinator {
	c.onVulnUpserted = cb
	return c
}

// FindPURLSource 找出第一个实现 PURLSource 的 source，按 name 匹配。
// 主要给 SyncByPURLs 用：当前仅 OSVSource 实现 PURLSource。
func (c *Coordinator) FindPURLSource(name string) PURLSource {
	for _, s := range c.sources {
		if s.Name() != name {
			continue
		}
		if ps, ok := s.(PURLSource); ok {
			return ps
		}
	}
	return nil
}

// Sync 拉取所有 source 自 since 起的 advisory，匹配 hosts 后入库。
//
// hosts 由调用方提供（来自 host_software 表的全量装包清单）。
// 返回总入库 vuln 数 + 受影响 host 关联数。
func (c *Coordinator) Sync(ctx context.Context, since time.Time, hosts []HostSoftware) (vulnCount, hostVulnCount int, err error) {
	// 每个 source 一 goroutine 并发拉取。各 source 是独立上游（apollo.build.resf.org /
	// access.redhat.com / security-tracker.debian.org / etc），互不抢限流。
	// 单 source 内仍串行翻页 + DoWithBackoff 处理 429/403/5xx，避免被任一上游限流。
	type fetchResult struct {
		src  Source
		advs []*Advisory
		err  error
		cost time.Duration
	}
	resultsCh := make(chan fetchResult, len(c.sources))
	var wg sync.WaitGroup
	for _, src := range c.sources {
		if c.checker != nil && !c.checker.IsEnabled(src.Name()) {
			c.logger.Debug("source 未启用，跳过", zap.String("source", src.Name()))
			continue
		}
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					c.logger.Error("source goroutine panic",
						zap.String("source", s.Name()),
						zap.Any("panic", r))
					resultsCh <- fetchResult{src: s, err: fmt.Errorf("panic: %v", r)}
				}
			}()
			srcStart := time.Now()
			if c.checker != nil {
				c.checker.MarkRunning(s.Name())
			}
			// 增量 sync：优先用 source 自己的 watermark，无 watermark 才退回调用方传的 since
			perSourceSince := since
			if c.checker != nil {
				if wm := c.checker.GetWatermark(s.Name()); !wm.IsZero() {
					perSourceSince = wm
				}
			}
			advs, ferr := s.Fetch(ctx, perSourceSince)
			resultsCh <- fetchResult{src: s, advs: advs, err: ferr, cost: time.Since(srcStart)}
		}(src)
	}
	wg.Wait()
	close(resultsCh)

	allAdvisories := make([]sourcedAdvisory, 0, 4096)
	for r := range resultsCh {
		if r.err != nil {
			c.logger.Warn("source fetch 失败，跳过", zap.String("source", r.src.Name()), zap.Error(r.err))
			if c.checker != nil {
				c.checker.MarkFailed(r.src.Name(), r.err)
			}
			continue
		}
		var maxIssued time.Time
		for _, adv := range r.advs {
			if !validateAdvisory(adv) {
				continue
			}
			if adv.IssuedAt.After(maxIssued) {
				maxIssued = adv.IssuedAt
			}
			allAdvisories = append(allAdvisories, sourcedAdvisory{
				sourceName: r.src.Name(),
				advisory:   adv,
				confidence: r.src.Confidence(),
			})
		}
		c.logger.Info("source 拉取完成",
			zap.String("source", r.src.Name()),
			zap.Int("count", len(r.advs)),
			zap.Duration("cost", r.cost),
		)
		if c.checker != nil {
			c.checker.MarkSuccess(r.src.Name(), int64(len(r.advs)), r.cost)
			// 推进 watermark 给下次增量 sync 用（仅在拉到 advisory 时推进）
			if !maxIssued.IsZero() {
				c.checker.SetWatermark(r.src.Name(), maxIssued)
			}
		}
	}

	// 按 CVE × host 合并去重（confidence 高者覆盖）
	merged := mergeByConfidence(allAdvisories, c.matcher, hosts)

	// 入库 vulnerabilities + host_vulnerabilities（每 CVE 一行；按 CVE 串行，避免行级锁竞争）
	for cveID, entry := range merged {
		if err := c.upsertVuln(cveID, entry); err != nil {
			c.logger.Warn("upsert vuln 失败", zap.String("cve", cveID), zap.Error(err))
			continue
		}
		vulnCount++
		hostVulnCount += len(entry.affectedHosts)
	}

	// 批量 upsert advisory_packages（一次 sync 可有几十万行，5000+ 单行 INSERT 太慢）
	apStart := time.Now()
	if apRows := c.bulkUpsertAdvisoryPackages(merged); apRows > 0 {
		c.logger.Info("advisory_packages 批量 upsert 完成",
			zap.Int("rows", apRows),
			zap.Duration("cost", time.Since(apStart)))
	}

	// upsertVuln 期间 mergeByConfidence 会翻新 vulnerabilities.source 字段，
	// 历史 host_vuln 行可能从 JOIN 角度变为 cross-OS/跨 major FP。
	// 同一份 cleanup 逻辑(advisory.CleanupHostVulnFP)既由 migration 启动时跑一次，
	// 又在每次 sync 后跑，确保 host_vuln 与新 source 归属一致。
	c.logger.Info("Coordinator.Sync 完成，跑 host_vuln FP 清理")
	CleanupHostVulnFP(c.db, c.logger)
	CleanupAlreadyPatched(c.db, c.logger)

	return vulnCount, hostVulnCount, nil
}

// IngestAdvisories 对一批「已拉取」的 advisory 做匹配 + 入库，不拉源。
//
// 供 Manager 的 Kafka consumer 复用：VulnSync 服务已从 advisory 源拉取并经 Kafka
// 投递富 advisory，consumer 反序列化成 AdvisoryMessage 后调用本方法。
// 走与 Sync 完全相同的 mergeByConfidence → upsertVuln → bulkUpsertAdvisoryPackages
// 写路径，保证「消费路径」与「自拉路径」产出的 host_vuln 集合等价。
//
// 注：本方法不跑 host_vuln FP 清理（CleanupHostVulnFP / CleanupAlreadyPatched）。
// 清理是全局操作，由调用方在批量 flush 后自行触发，避免逐消息重复全表扫描。
func (c *Coordinator) IngestAdvisories(msgs []AdvisoryMessage, hosts []HostSoftware) (vulnCount, hostVulnCount int) {
	items := make([]sourcedAdvisory, 0, len(msgs))
	for _, m := range msgs {
		if m.Advisory == nil || !validateAdvisory(m.Advisory) {
			continue
		}
		items = append(items, sourcedAdvisory{
			sourceName: m.Source,
			advisory:   m.Advisory,
			confidence: m.Confidence,
		})
	}
	if len(items) == 0 {
		return 0, 0
	}

	merged := mergeByConfidence(items, c.matcher, hosts)
	for cveID, entry := range merged {
		if err := c.upsertVuln(cveID, entry); err != nil {
			c.logger.Warn("ingest upsert vuln 失败", zap.String("cve", cveID), zap.Error(err))
			continue
		}
		vulnCount++
		hostVulnCount += len(entry.affectedHosts)
	}
	if apRows := c.bulkUpsertAdvisoryPackages(merged); apRows > 0 {
		c.logger.Debug("ingest advisory_packages 批量 upsert", zap.Int("rows", apRows))
	}
	return vulnCount, hostVulnCount
}

// validateAdvisory 入库前严格校验，过滤无效 advisory。
func validateAdvisory(adv *Advisory) bool {
	if adv == nil || len(adv.CVEIDs) == 0 {
		return false
	}
	if len(adv.AffectedPkgs) == 0 {
		return false
	}
	for _, p := range adv.AffectedPkgs {
		if p.Name == "" || p.FixedVersion == "" {
			return false
		}
	}
	// 防 OS-mismatch 漏网：如 advisory.Description 含 "Windows" 且 OS 是 Linux 系
	if isLinuxOS(adv.OSFamily) && containsCaseInsensitive(adv.Description, "Microsoft Windows") {
		return false
	}
	return true
}

func isLinuxOS(family string) bool {
	switch strings.ToLower(family) {
	case "rhel", "rocky", "centos", "centos-stream", "almalinux",
		"oraclelinux", "ubuntu", "debian", "alpine",
		// 信创 OS
		"openeuler", "anolis", "openanolis", "kylin", "uos", "tencentos":
		return true
	}
	return false
}

func containsCaseInsensitive(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

type sourcedAdvisory struct {
	sourceName string
	advisory   *Advisory
	confidence Confidence
}

type mergedVuln struct {
	// CVE 元数据：来自 confidence 最高的 advisory（仅 description/severity/CVSS 等）
	advisory   *Advisory
	confidence Confidence
	source     string

	// 受影响主机：所有 source 的并集（去重）。
	// 关键：同 CVE 在 RHSA(rhel,10) 和 Rocky(rocky,9) 各自 match 不同 host，
	// 必须并集而非择一，否则 Rocky host 漏报。
	affectedHosts []AffectedHost

	// 所有产生该 CVE 的 advisory（按 source 区分），用于写 advisory_packages。
	// 每条 advisory 含其 OS/source/pkg 信息。
	allAdvisories []sourcedAdvisory
}

// mergeByConfidence 按 CVE 维度合并 advisory，affectedHosts 跨 source 并集去重。
//
// 与旧实现的关键差异：
//   - 旧：同 CVE 同 confidence 时后者跳过 → Rocky/RHSA 互斥（覆盖问题）
//   - 新：affectedHosts 总是 union；CVE 元数据按 confidence 排序后第一条胜出
//   - 新：保留所有 advisory 供 upsertVuln 写 advisory_packages（OS-specific fix 不丢失）
func mergeByConfidence(items []sourcedAdvisory, matcher Matcher, hosts []HostSoftware) map[string]*mergedVuln {
	out := make(map[string]*mergedVuln)
	// 排序：confidence 高者前置，确保 metadata 由高 confidence 决定
	sort.SliceStable(items, func(i, j int) bool {
		return confidenceRank(items[i].confidence) > confidenceRank(items[j].confidence)
	})

	for _, item := range items {
		affected := matcher.Match(item.advisory, hosts)
		needs := make([]AffectedHost, 0, len(affected))
		for _, a := range affected {
			if a.NeedsUpdate {
				needs = append(needs, a)
			}
		}
		for _, cveID := range item.advisory.CVEIDs {
			existing, ok := out[cveID]
			if !ok {
				out[cveID] = &mergedVuln{
					advisory:      item.advisory,
					confidence:    item.confidence,
					source:        item.sourceName,
					affectedHosts: needs,
					allAdvisories: []sourcedAdvisory{item},
				}
				continue
			}
			// 受影响主机并集（不论 confidence）
			existing.affectedHosts = append(existing.affectedHosts, needs...)
			existing.allAdvisories = append(existing.allAdvisories, item)
			// metadata 仅在严格更高 confidence 时覆盖
			if confidenceRank(item.confidence) > confidenceRank(existing.confidence) {
				existing.advisory = item.advisory
				existing.confidence = item.confidence
				existing.source = item.sourceName
			}
		}
	}
	// affectedHosts 去重（host_id + pkg_name 唯一）
	for _, mv := range out {
		mv.affectedHosts = dedupAffectedHosts(mv.affectedHosts)
	}
	return out
}

// dedupAffectedHosts 按 (HostID, PkgName) 去重，保留首条
func dedupAffectedHosts(in []AffectedHost) []AffectedHost {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]AffectedHost, 0, len(in))
	for _, a := range in {
		k := a.HostID + "|" + a.PkgName
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, a)
	}
	return out
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	}
	return 0
}

// upsertVuln 写入 vulnerabilities + host_vulnerabilities。
//
// 对 PURL-based advisory（OSV，含 OsvID/PURL/AttackVector/VulnType/AffectedVersions）
// 额外写这 5 个列；OS advisory 字段为空，覆写空也无碍（旧值不会被 dirty）。
func (c *Coordinator) upsertVuln(cveID string, entry *mergedVuln) error {
	if entry == nil {
		return nil
	}
	adv := entry.advisory
	component := ""
	currentVer := ""
	fixedVer := ""
	if len(adv.AffectedPkgs) > 0 {
		component = adv.AffectedPkgs[0].Name
		fixedVer = adv.AffectedPkgs[0].FixedVersion
	}
	// PURL-based source（OSV）：优先用 advisory.CurrentVersion（命中 PURL 携带的版本）
	if adv.CurrentVersion != "" {
		currentVer = adv.CurrentVersion
	} else if len(entry.affectedHosts) > 0 {
		currentVer = entry.affectedHosts[0].InstalledVer
	}

	vuln := &model.Vulnerability{
		CveID:            cveID,
		OsvID:            adv.OsvID,
		PURL:             adv.PURL,
		Severity:         string(adv.Severity),
		CvssScore:        adv.CVSSScore,
		CvssVector:       adv.CVSSVector,
		AttackVector:     adv.AttackVector,
		VulnType:         adv.VulnType,
		AffectedVersions: adv.AffectedVersions,
		Component:        component,
		Description:      adv.Description,
		Status:           "unpatched",
		DiscoveredAt:     model.LocalTime(adv.IssuedAt),
		CurrentVersion:   currentVer,
		FixedVersion:     fixedVer,
		ReferenceUrl:     adv.ReferenceURL,
		Source:           entry.source,
		PatchAvailable:   fixedVer != "",
		Confidence:       string(entry.confidence),
		AffectedHosts:    len(entry.affectedHosts),
	}

	assign := map[string]any{
		"severity":        vuln.Severity,
		"cvss_score":      vuln.CvssScore,
		"cvss_vector":     vuln.CvssVector,
		"component":       vuln.Component,
		"description":     vuln.Description,
		"current_version": vuln.CurrentVersion,
		"fixed_version":   vuln.FixedVersion,
		"reference_url":   vuln.ReferenceUrl,
		"source":          vuln.Source,
		"patch_available": vuln.PatchAvailable,
		"confidence":      vuln.Confidence,
		"affected_hosts":  vuln.AffectedHosts,
	}

	// 防止 OS source 覆盖 ecosystem source 的 vulnerabilities.source。
	//
	// 历史 bug：debian-tracker (confidence=high) sync 同 cveID 时，
	// upsertVuln Assign 把 OSV (confidence=medium) 写入的 source="osv" 覆盖为
	// source="debian-tracker"。后续 CleanupHostVulnFP 看到 debian source 关联
	// rocky host → 误判跨 OS → 删 host_vuln。结果 OSV 发现的 Java/npm 漏洞被错删。
	//
	// 修复：若 OS source advisory 的 cveID 在 DB 已有 PURL 字段（说明 OSV/语言包路径
	// 已先入库），不覆盖 source / purl / osv_id 等 ecosystem 维度字段，仅补 metadata
	// （description / cvss / severity 等）。
	if entry.source != "osv" && entry.source != "nvd" && adv.Ecosystem == "" {
		var existing model.Vulnerability
		err := c.db.Where("cve_id = ?", cveID).Select("id, source, purl").First(&existing).Error
		if err == nil && existing.PURL != "" && strings.HasPrefix(existing.PURL, "pkg:") {
			// 已被 OSV/PURL 路径写过：保留 ecosystem source 字段
			delete(assign, "source")
			// component 也不覆盖（OSV PURL 包名更精确，OS source 的 component 是 OS pkg 名）
			delete(assign, "component")
		}
	}
	// OSV 字段仅在非空时回写（避免 OS source 覆盖 OSV 已写入的 osv_id 等）
	if adv.OsvID != "" {
		assign["osv_id"] = vuln.OsvID
	}
	if adv.PURL != "" {
		assign["purl"] = vuln.PURL
	}
	if adv.AttackVector != "" {
		assign["attack_vector"] = vuln.AttackVector
	}
	if adv.VulnType != "" {
		assign["vuln_type"] = vuln.VulnType
	}
	if adv.AffectedVersions != "" {
		assign["affected_versions"] = vuln.AffectedVersions
	}

	if err := c.db.Where("cve_id = ?", cveID).
		Assign(assign).
		FirstOrCreate(vuln).Error; err != nil {
		return fmt.Errorf("upsert vuln: %w", err)
	}

	// 注：advisory_packages 改为 sync 末尾批量 upsert（一次 sync 可数十万行，单行 upsert 太慢）

	// 关联 host
	for _, a := range entry.affectedHosts {
		hv := &model.HostVulnerability{
			VulnID:         vuln.ID,
			HostID:         a.HostID,
			CurrentVersion: a.InstalledVer,
			Status:         "unpatched",
		}
		if err := c.db.Where("vuln_id = ? AND host_id = ?", vuln.ID, a.HostID).
			Assign(map[string]any{
				"current_version": hv.CurrentVersion,
				"status":          hv.Status,
			}).
			FirstOrCreate(hv).Error; err != nil {
			c.logger.Warn("upsert host_vuln 失败",
				zap.Uint("vuln_id", vuln.ID),
				zap.String("host_id", a.HostID),
				zap.Error(err))
		}
	}

	// 触发可选回调（异步通报 / 通知）
	if c.onVulnUpserted != nil {
		c.onVulnUpserted(vuln, adv)
	}
	return nil
}

// bulkUpsertAdvisoryPackages 把 merged 里所有 advisory 摊平成 (cve, source, OS, pkg, arch)
// 行后批量 INSERT ON DUPLICATE KEY UPDATE。
//
// 与原 upsertAdvisoryPackages（每行 Where+FirstOrCreate）相比：
//   - 网络往返从 N 次 → ceil(N/batchSize) 次（batchSize=500）
//   - 单 sync 5-30 万行场景：30+ 分钟 → ~30 秒
//   - 走 GORM Clauses.OnConflict 等价 ON DUPLICATE KEY UPDATE（依赖 advisory_packages
//     的 6 列 UNIQUE 索引）
//
// 返回成功 upsert 的逻辑行数（实际 INSERT/UPDATE 次数 = len(rows)）。
func (c *Coordinator) bulkUpsertAdvisoryPackages(merged map[string]*mergedVuln) int {
	rows := make([]model.AdvisoryPackage, 0, len(merged)*4)
	seen := make(map[string]struct{}, len(merged)*4)
	for cveID, entry := range merged {
		if entry == nil {
			continue
		}
		for _, sa := range entry.allAdvisories {
			adv := sa.advisory
			if adv == nil {
				continue
			}
			var issuedAt *model.LocalTime
			if !adv.IssuedAt.IsZero() {
				t := model.LocalTime(adv.IssuedAt)
				issuedAt = &t
			}
			for _, fix := range adv.AffectedPkgs {
				if fix.Name == "" || fix.FixedVersion == "" {
					continue
				}
				// 同 sync 内 (cve,source,os,major,pkg,arch) 重复 fix 去重，避免 ON DUPLICATE 冲突
				key := cveID + "|" + sa.sourceName + "|" + adv.OSFamily + "|" + adv.OSMajorVer + "|" + fix.Name + "|" + fix.Arch
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				rows = append(rows, model.AdvisoryPackage{
					CveID:            cveID,
					Source:           sa.sourceName,
					SourceAdvisoryID: adv.AdvisoryID,
					OSFamily:         adv.OSFamily,
					OSMajor:          adv.OSMajorVer,
					Ecosystem:        adv.Ecosystem,
					PkgName:          fix.Name,
					Arch:             fix.Arch,
					FixedVersion:     fix.FixedVersion,
					Confidence:       string(sa.confidence),
					Severity:         string(adv.Severity),
					IssuedAt:         issuedAt,
				})
			}
		}
	}
	if len(rows) == 0 {
		return 0
	}
	const batchSize = 500
	if err := c.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "cve_id"}, {Name: "source"}, {Name: "os_family"},
			{Name: "os_major"}, {Name: "pkg_name"}, {Name: "arch"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"source_advisory_id", "ecosystem", "fixed_version",
			"confidence", "severity", "issued_at", "updated_at",
		}),
	}).CreateInBatches(rows, batchSize).Error; err != nil {
		c.logger.Warn("bulk upsert advisory_packages 失败", zap.Error(err), zap.Int("rows", len(rows)))
		return 0
	}
	return len(rows)
}

// PURLPkgInfo 单个 PURL 命中后用于写 host_vuln 的元信息。
type PURLPkgInfo struct {
	PkgName  string   // pkg 名（写 vulnerabilities.component）
	Version  string   // 当前装版本（写 host_vulnerabilities.current_version）
	HostIDs  []string // 命中该 PURL 的所有 host_id
	Hostname map[string]string
	IP       map[string]string
}

// SyncByPURLs PURL 模式漏洞同步路径（OSV / 未来 GHSA 等）。
//
// 与 Sync 不同：
//   - 数据来源：PURLSource.FetchByPURLs（按 PURL 查 osv.dev）
//   - host 关联：直接用 purlPkgInfo[purl].HostIDs（PURL 已精确）
//     不走 matcher gate（matcher 用于时间增量 advisory，PURL 自带精确性）
//   - 仍走 upsertVuln + bulkUpsertAdvisoryPackages 同一 DB 写路径
//   - 触发 onVulnUpserted callback（bulletin / 通知）
//
// 参数：
//
//	purls         去重 PURL 列表（调用方应已 FilterOSVPURLs）
//	purlPkgInfo   purl → PURLPkgInfo（host_id 关联 + pkg 名/版本）
//	knownVulnIDs  已入库 vuln ID 集合（OSVSource 跳过 detail HTTP 用，可为 nil）
//	sourceName    要使用的 PURLSource 名（一般 "osv"）
//
// 返回：处理 PURL 数 + upsert vuln 数 + 写入 host_vuln 关联数。
func (c *Coordinator) SyncByPURLs(ctx context.Context, sourceName string, purls []string,
	purlPkgInfo map[string]PURLPkgInfo, knownVulnIDs map[string]struct{}) (purlCount, vulnCount, hostVulnCount int, err error) {
	src := c.FindPURLSource(sourceName)
	if src == nil {
		return 0, 0, 0, fmt.Errorf("PURLSource %q not registered", sourceName)
	}

	// 注入 known IDs（仅 OSVSource 内部使用此优化）
	if osv, ok := src.(*OSVSource); ok && knownVulnIDs != nil {
		osv.WithKnownVulnIDs(knownVulnIDs)
	}

	c.logger.Info("PURL 漏洞同步开始", zap.String("source", sourceName), zap.Int("purl_count", len(purls)))
	srcStart := time.Now()
	if c.checker != nil {
		c.checker.MarkRunning(sourceName)
	}

	purlToAdvs, ferr := src.FetchByPURLs(ctx, purls)
	if ferr != nil {
		if c.checker != nil {
			c.checker.MarkFailed(sourceName, ferr)
		}
		return 0, 0, 0, fmt.Errorf("PURLSource fetch: %w", ferr)
	}

	// 统计 advisory 总数（含 known minimal entries）
	var totalAdv int
	for _, advs := range purlToAdvs {
		totalAdv += len(advs)
	}

	// 写入：每个 PURL 的每条 advisory 关联其 PURL 命中的所有 host_id
	// 同 CVE 重复出现时 upsertVuln 会 update（ON DUPLICATE KEY）
	mergedForAP := make(map[string]*mergedVuln) // 仅供 bulkUpsertAdvisoryPackages 用
	for purl, advs := range purlToAdvs {
		info, ok := purlPkgInfo[purl]
		if !ok || len(info.HostIDs) == 0 {
			continue
		}
		for _, adv := range advs {
			if adv == nil {
				continue
			}
			affected := make([]AffectedHost, 0, len(info.HostIDs))
			for _, hid := range info.HostIDs {
				affected = append(affected, AffectedHost{
					HostID:       hid,
					PkgName:      info.PkgName,
					InstalledVer: info.Version,
					NeedsUpdate:  true,
				})
			}
			// affected.FixedVersion: 取 advisory 第一个 fix（detailToAdvisory 已填）
			if len(adv.AffectedPkgs) > 0 {
				fv := adv.AffectedPkgs[0].FixedVersion
				for i := range affected {
					affected[i].FixedVersion = fv
				}
			}

			entry := &mergedVuln{
				advisory:      adv,
				confidence:    src.Confidence(),
				source:        src.Name(),
				affectedHosts: affected,
				allAdvisories: []sourcedAdvisory{{sourceName: src.Name(), advisory: adv, confidence: src.Confidence()}},
			}
			purlCount++

			// minimal advisory（known ID 无 detail）跳过 upsertVuln，仅做 host_vuln 关联
			if len(adv.CVEIDs) == 0 && adv.AffectedPkgs == nil {
				if hvAdded := c.relinkHostVulnByOsvID(adv.OsvID, affected); hvAdded > 0 {
					hostVulnCount += hvAdded
				}
				continue
			}

			for _, cveID := range adv.CVEIDs {
				if err := c.upsertVuln(cveID, entry); err != nil {
					c.logger.Warn("upsert vuln 失败", zap.String("cve", cveID), zap.Error(err))
					continue
				}
				vulnCount++
				hostVulnCount += len(affected)
				mergedForAP[cveID] = entry
			}
		}
	}

	// advisory_packages 批量 upsert（PURL 模式下 OS 字段空，仅入 ecosystem 维度）
	apStart := time.Now()
	if apRows := c.bulkUpsertAdvisoryPackages(mergedForAP); apRows > 0 {
		c.logger.Info("advisory_packages PURL 批量 upsert 完成",
			zap.Int("rows", apRows),
			zap.Duration("cost", time.Since(apStart)))
	}

	if c.checker != nil {
		c.checker.MarkSuccess(sourceName, int64(totalAdv), time.Since(srcStart))
	}
	c.logger.Info("PURL 漏洞同步完成",
		zap.String("source", sourceName),
		zap.Int("purl_count", purlCount),
		zap.Int("vuln_upsert", vulnCount),
		zap.Int("host_vuln_links", hostVulnCount),
		zap.Duration("cost", time.Since(srcStart)))
	return purlCount, vulnCount, hostVulnCount, nil
}

// relinkHostVulnByOsvID 对 minimal advisory（仅 OsvID + PURL），找现有 vulnerabilities 行 ID
// 后写入 host_vuln 关联。命中 0 行不报错（advisory 可能尚未入库）。
func (c *Coordinator) relinkHostVulnByOsvID(osvID string, affected []AffectedHost) int {
	if osvID == "" {
		return 0
	}
	var vulnIDs []uint
	c.db.Model(&model.Vulnerability{}).
		Where("osv_id = ? OR cve_id = ?", osvID, osvID).
		Pluck("id", &vulnIDs)
	if len(vulnIDs) == 0 {
		return 0
	}
	added := 0
	for _, vid := range vulnIDs {
		for _, a := range affected {
			hv := &model.HostVulnerability{
				VulnID:         vid,
				HostID:         a.HostID,
				CurrentVersion: a.InstalledVer,
				Status:         "unpatched",
			}
			if err := c.db.Where("vuln_id = ? AND host_id = ?", vid, a.HostID).
				Assign(map[string]any{
					"current_version": hv.CurrentVersion,
					"status":          hv.Status,
				}).
				FirstOrCreate(hv).Error; err == nil {
				added++
			}
		}
	}
	return added
}
