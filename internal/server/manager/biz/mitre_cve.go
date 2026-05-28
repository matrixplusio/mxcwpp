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
)

// MITRECVEEnricher 用 MITRE CVE Services API 按 cve_id 拉详情补全 vuln 元数据。
//
// API: https://cveawg.mitre.org/api/cve/{CVE-ID}
//   - 单条 200 OK，无 rate limit 公开免费
//   - 国外服务器可达（CDN）
//   - 内容含 descriptions / metrics (CVSS v3.1) / references / problemTypes (CWE)
//
// 用途：作为 NVD 替代的 CVE 元数据源（NVD rate-limit + 国外不通）。
type MITRECVEEnricher struct {
	db      *gorm.DB
	logger  *zap.Logger
	client  *http.Client
	baseURL string
}

// NewMITRECVEEnricher 构造默认。
func NewMITRECVEEnricher(db *gorm.DB, logger *zap.Logger) *MITRECVEEnricher {
	return &MITRECVEEnricher{
		db:      db,
		logger:  logger,
		client:  &http.Client{Timeout: 15 * time.Second},
		baseURL: "https://cveawg.mitre.org/api/cve",
	}
}

// mitreCVE MITRE CVE Records v5 schema (部分)。
type mitreCVE struct {
	CVEMetadata struct {
		CVEID         string `json:"cveId"`
		State         string `json:"state"`
		AssignerOrgID string `json:"assignerOrgId"`
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Title        string             `json:"title"`
			Descriptions []mitreDescription `json:"descriptions"`
			Metrics      []mitreMetric      `json:"metrics"`
			References   []mitreReference   `json:"references"`
			ProblemTypes []mitreProblemType `json:"problemTypes"`
		} `json:"cna"`
	} `json:"containers"`
}

type mitreDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type mitreMetric struct {
	Format    string              `json:"format"`
	Scenarios []map[string]string `json:"scenarios,omitempty"`
	CVSSv31   *mitreCVSSData      `json:"cvssV3_1,omitempty"`
	CVSSv30   *mitreCVSSData      `json:"cvssV3_0,omitempty"`
}

type mitreCVSSData struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

type mitreReference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags,omitempty"`
}

type mitreProblemType struct {
	Descriptions []struct {
		Lang        string `json:"lang"`
		Description string `json:"description"`
		CWEID       string `json:"cweId,omitempty"`
		Type        string `json:"type,omitempty"`
	} `json:"descriptions"`
}

// SyncMITRECVE 用 MITRE API 补全所有 description/cvss 字段不完整的 vuln。
// 仅处理 ≤2000 条避免超时；下次再跑可补剩余。
func (v *VulnScanner) SyncMITRECVE() error {
	_, err := v.SyncMITRECVECounted()
	return err
}

// SyncMITRECVECounted 返回实际 enriched vuln 数（供 last_count 显示）。
func (v *VulnScanner) SyncMITRECVECounted() (int64, error) {
	enricher := NewMITRECVEEnricher(v.db, v.logger)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return enricher.RunCounted(ctx, 2000)
}

// Run 拉取待补全的 vuln 列表，按 cve_id 批量 fetch + UPDATE。
func (e *MITRECVEEnricher) Run(ctx context.Context, maxCount int) error {
	_, err := e.RunCounted(ctx, maxCount)
	return err
}

// RunCounted 同 Run，返回实际 enriched vuln 行数。
func (e *MITRECVEEnricher) RunCounted(ctx context.Context, maxCount int) (int64, error) {
	type row struct {
		CveID string
	}
	var rows []row
	if err := e.db.Table("vulnerabilities").
		Select("cve_id").
		Where("deleted_at IS NULL AND cve_id LIKE 'CVE-%' AND (description IS NULL OR description = '' OR LENGTH(description) < 50 OR cvss_score = 0)").
		Order("RAND()").
		Limit(maxCount).
		Find(&rows).Error; err != nil {
		return 0, fmt.Errorf("查询待补全 vuln 失败: %w", err)
	}
	if len(rows) == 0 {
		e.logger.Info("MITRE CVE 元数据：无待补全的 vuln")
		return 0, nil
	}

	var enriched int64
	for _, r := range rows {
		select {
		case <-ctx.Done():
			return enriched, ctx.Err()
		default:
		}
		n, err := e.enrichOne(ctx, r.CveID)
		if err != nil {
			e.logger.Debug("MITRE 拉取失败，跳过", zap.String("cve", r.CveID), zap.Error(err))
			continue
		}
		enriched += n
		time.Sleep(50 * time.Millisecond)
	}
	e.logger.Info("MITRE CVE 元数据增强完成",
		zap.Int("attempted", len(rows)),
		zap.Int64("enriched", enriched),
	)
	return enriched, nil
}

// enrichOne 拉单条 CVE 详情 UPDATE 现有 vuln。
func (e *MITRECVEEnricher) enrichOne(ctx context.Context, cveID string) (int64, error) {
	url := e.baseURL + "/" + cveID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mxsec-platform/1.0")
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("MITRE HTTP %d", resp.StatusCode)
	}
	var d mitreCVE
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return 0, fmt.Errorf("MITRE decode: %w", err)
	}

	description := extractMITREDescription(d.Containers.CNA.Descriptions)
	cvssScore, cvssVector, severity := extractMITRECVSS(d.Containers.CNA.Metrics)
	cweID := extractMITRECWE(d.Containers.CNA.ProblemTypes)
	refURL := extractMITREReference(d.Containers.CNA.References)

	updates := map[string]any{}
	if description != "" {
		updates["description"] = description
	}
	if cvssScore > 0 {
		updates["cvss_score"] = cvssScore
	}
	if cvssVector != "" {
		updates["cvss_vector"] = cvssVector
	}
	if severity != "" {
		updates["severity"] = severity
	}
	if cweID != "" {
		updates["cwe_id"] = cweID
	}
	if refURL != "" && !strings.Contains(refURL, "errata.rockylinux.org") && !strings.Contains(refURL, "access.redhat.com") {
		// 不覆盖 OS Advisory 已填的 reference_url（更具体）
		updates["reference_url"] = refURL
	}
	if len(updates) == 0 {
		return 0, nil
	}

	result := e.db.Table("vulnerabilities").
		Where("cve_id = ?", cveID).
		Updates(updates)
	return result.RowsAffected, result.Error
}

func extractMITREDescription(descs []mitreDescription) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descs) > 0 {
		return descs[0].Value
	}
	return ""
}

func extractMITRECVSS(metrics []mitreMetric) (float64, string, string) {
	for _, m := range metrics {
		if m.CVSSv31 != nil && m.CVSSv31.BaseScore > 0 {
			return m.CVSSv31.BaseScore, m.CVSSv31.VectorString, normalizeSeverityLabel(m.CVSSv31.BaseSeverity)
		}
	}
	for _, m := range metrics {
		if m.CVSSv30 != nil && m.CVSSv30.BaseScore > 0 {
			return m.CVSSv30.BaseScore, m.CVSSv30.VectorString, normalizeSeverityLabel(m.CVSSv30.BaseSeverity)
		}
	}
	return 0, "", ""
}

func extractMITRECWE(types []mitreProblemType) string {
	for _, t := range types {
		for _, d := range t.Descriptions {
			if d.CWEID != "" {
				return d.CWEID
			}
			if strings.HasPrefix(d.Description, "CWE-") {
				return d.Description
			}
		}
	}
	return ""
}

func extractMITREReference(refs []mitreReference) string {
	for _, r := range refs {
		for _, tag := range r.Tags {
			if tag == "vendor-advisory" || tag == "patch" {
				return r.URL
			}
		}
	}
	if len(refs) > 0 {
		return refs[0].URL
	}
	return ""
}
