package advisory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// EnabledChecker 判断 source 是否启用 + 写回同步状态。
// 由 biz.VulnDataSourceService 实现，coordinator 通过接口注入解耦。
type EnabledChecker interface {
	IsEnabled(name string) bool
	MarkRunning(name string)
	MarkSuccess(name string, count int64, duration time.Duration)
	MarkFailed(name string, err error)
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
}

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

// Sync 拉取所有 source 自 since 起的 advisory，匹配 hosts 后入库。
//
// hosts 由调用方提供（来自 host_software 表的全量装包清单）。
// 返回总入库 vuln 数 + 受影响 host 关联数。
func (c *Coordinator) Sync(ctx context.Context, since time.Time, hosts []HostSoftware) (vulnCount, hostVulnCount int, err error) {
	allAdvisories := make([]sourcedAdvisory, 0, 4096)

	for _, src := range c.sources {
		// enabled check：disabled 直接跳过
		if c.checker != nil && !c.checker.IsEnabled(src.Name()) {
			c.logger.Debug("source 未启用，跳过", zap.String("source", src.Name()))
			continue
		}
		srcStart := time.Now()
		if c.checker != nil {
			c.checker.MarkRunning(src.Name())
		}
		advs, err := src.Fetch(ctx, since)
		if err != nil {
			c.logger.Warn("source fetch 失败，跳过", zap.String("source", src.Name()), zap.Error(err))
			if c.checker != nil {
				c.checker.MarkFailed(src.Name(), err)
			}
			continue
		}
		for _, adv := range advs {
			if !validateAdvisory(adv) {
				continue
			}
			allAdvisories = append(allAdvisories, sourcedAdvisory{
				src:        src,
				advisory:   adv,
				confidence: src.Confidence(),
			})
		}
		c.logger.Info("source 拉取完成",
			zap.String("source", src.Name()),
			zap.Int("count", len(advs)),
		)
		if c.checker != nil {
			c.checker.MarkSuccess(src.Name(), int64(len(advs)), time.Since(srcStart))
		}
	}

	// 按 CVE × host 合并去重（confidence 高者覆盖）
	merged := mergeByConfidence(allAdvisories, c.matcher, hosts)

	// 入库
	for cveID, entry := range merged {
		if err := c.upsertVuln(cveID, entry); err != nil {
			c.logger.Warn("upsert vuln 失败", zap.String("cve", cveID), zap.Error(err))
			continue
		}
		vulnCount++
		hostVulnCount += len(entry.affectedHosts)
	}
	return vulnCount, hostVulnCount, nil
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
		"oraclelinux", "ubuntu", "debian", "alpine":
		return true
	}
	return false
}

func containsCaseInsensitive(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

type sourcedAdvisory struct {
	src        Source
	advisory   *Advisory
	confidence Confidence
}

type mergedVuln struct {
	advisory      *Advisory
	confidence    Confidence
	source        string
	affectedHosts []AffectedHost
}

// mergeByConfidence 按 CVE 维度合并 advisory，confidence 高者覆盖。
func mergeByConfidence(items []sourcedAdvisory, matcher Matcher, hosts []HostSoftware) map[string]*mergedVuln {
	out := make(map[string]*mergedVuln)
	// 先按 confidence 排序：high > medium > low
	sort.SliceStable(items, func(i, j int) bool {
		return confidenceRank(items[i].confidence) > confidenceRank(items[j].confidence)
	})

	for _, item := range items {
		affected := matcher.Match(item.advisory, hosts)
		// 仅保留 NeedsUpdate
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
					source:        item.src.Name(),
					affectedHosts: needs,
				}
				continue
			}
			// 已存在：低 confidence 不覆盖
			if confidenceRank(item.confidence) <= confidenceRank(existing.confidence) {
				continue
			}
			existing.advisory = item.advisory
			existing.confidence = item.confidence
			existing.source = item.src.Name()
			existing.affectedHosts = needs
		}
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
	if len(entry.affectedHosts) > 0 {
		currentVer = entry.affectedHosts[0].InstalledVer
	}

	vuln := &model.Vulnerability{
		CveID:          cveID,
		Severity:       string(adv.Severity),
		CvssScore:      adv.CVSSScore,
		CvssVector:     adv.CVSSVector,
		Component:      component,
		Description:    adv.Description,
		Status:         "unpatched",
		DiscoveredAt:   model.LocalTime(adv.IssuedAt),
		CurrentVersion: currentVer,
		FixedVersion:   fixedVer,
		ReferenceUrl:   adv.ReferenceURL,
		Source:         entry.source,
		PatchAvailable: fixedVer != "",
		Confidence:     string(entry.confidence),
		AffectedHosts:  len(entry.affectedHosts),
	}

	if err := c.db.Where("cve_id = ?", cveID).
		Assign(map[string]any{
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
		}).
		FirstOrCreate(vuln).Error; err != nil {
		return fmt.Errorf("upsert vuln: %w", err)
	}

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
	return nil
}
