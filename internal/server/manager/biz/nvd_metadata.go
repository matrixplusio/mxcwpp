package biz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// SyncNVDMetadata 用 NVD API 2.0 拉取近期修改的 CVE，按 cve_id UPDATE 已有 vuln 主表，
// 不入独立行。仅补全 description / cvss_score / cvss_vector / cwe / reference_url 等元数据。
//
// 用途：OS Advisory（RHSA/Rocky/USN/Debian）提供精确 component+fixed_version，
// 但 description 经常是 advisory 套话；NVD 给标准 CVE 描述 + CVSS 分数，
// 两者按 cve_id 合并形成完整漏洞画像。
//
// API: https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=...&lastModEndDate=...
// 无 API key：5 req / 30s，加 API key (NVD_API_KEY env) 提到 50 req / 30s。
//
// 增量同步：默认拉近 7 天 lastModified，初次同步可按需扩展。
func (v *VulnScanner) SyncNVDMetadata() error {
	_, err := v.SyncNVDMetadataCounted()
	return err
}

// SyncNVDMetadataCounted 同 SyncNVDMetadata，返回实际 enriched vuln 数。
func (v *VulnScanner) SyncNVDMetadataCounted() (int64, error) {
	apiKey := getEnvOr("NVD_API_KEY", "")
	enricher := newNVDMetadataEnricher(v.db, v.logger, apiKey)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return enricher.RunCounted(ctx, 7*24*time.Hour)
}

// nvdMetadataEnricher NVD CVE 元数据增强器。
type nvdMetadataEnricher struct {
	db      *gorm.DB
	logger  *zap.Logger
	client  *http.Client
	apiKey  string
	baseURL string
}

func newNVDMetadataEnricher(db *gorm.DB, logger *zap.Logger, apiKey string) *nvdMetadataEnricher {
	return &nvdMetadataEnricher{
		db:      db,
		logger:  logger,
		client:  &http.Client{Timeout: 60 * time.Second},
		apiKey:  apiKey,
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
	}
}

// nvdAPIResp NVD API 2.0 响应。
type nvdAPIResp struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []nvdAPIVulnEnv `json:"vulnerabilities"`
}

type nvdAPIVulnEnv struct {
	CVE nvdAPICVE `json:"cve"`
}

type nvdAPICVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	LastModified string           `json:"lastModified"`
	Descriptions []nvdAPIDesc     `json:"descriptions"`
	Metrics      nvdAPIMetrics    `json:"metrics"`
	Weaknesses   []nvdAPIWeakness `json:"weaknesses"`
	References   []nvdAPIRef      `json:"references"`
}

type nvdAPIDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdAPIMetrics struct {
	CVSSMetricV31 []nvdAPICVSS `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdAPICVSS `json:"cvssMetricV30"`
}

type nvdAPICVSS struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdAPIWeakness struct {
	Description []nvdAPIDesc `json:"description"`
}

type nvdAPIRef struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// Run 按 lookback 时窗拉取 NVD recently modified CVE，UPDATE 现有 vuln 主表。
func (e *nvdMetadataEnricher) Run(ctx context.Context, lookback time.Duration) error {
	_, err := e.RunCounted(ctx, lookback)
	return err
}

// RunCounted 同 Run，返回 enriched vuln 行数。
func (e *nvdMetadataEnricher) RunCounted(ctx context.Context, lookback time.Duration) (int64, error) {
	end := time.Now().UTC()
	start := end.Add(-lookback)

	startStr := start.Format("2006-01-02T15:04:05.000")
	endStr := end.Format("2006-01-02T15:04:05.000")

	const pageSize = 2000
	startIndex := 0
	var totalEnriched int64

	for {
		select {
		case <-ctx.Done():
			return totalEnriched, ctx.Err()
		default:
		}

		url := fmt.Sprintf("%s?lastModStartDate=%s&lastModEndDate=%s&resultsPerPage=%d&startIndex=%d",
			e.baseURL, startStr, endStr, pageSize, startIndex)
		page, err := e.fetchPage(ctx, url)
		if err != nil {
			e.logger.Warn("NVD 元数据拉取失败", zap.Error(err))
			break
		}
		if len(page.Vulnerabilities) == 0 {
			break
		}

		for _, item := range page.Vulnerabilities {
			totalEnriched += e.enrichOne(&item.CVE)
		}

		startIndex += pageSize
		if startIndex >= page.TotalResults {
			break
		}
		if e.apiKey == "" {
			time.Sleep(6500 * time.Millisecond)
		} else {
			time.Sleep(700 * time.Millisecond)
		}
	}

	e.logger.Info("NVD 元数据增强完成",
		zap.Int64("vuln_updated", totalEnriched),
		zap.Duration("lookback", lookback),
	)
	return totalEnriched, nil
}

// fetchPage 拉单页 NVD API 响应。
func (e *nvdMetadataEnricher) fetchPage(ctx context.Context, url string) (*nvdAPIResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if e.apiKey != "" {
		req.Header.Set("apiKey", e.apiKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("NVD API rate limited HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API HTTP %d", resp.StatusCode)
	}
	var page nvdAPIResp
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("NVD decode: %w", err)
	}
	return &page, nil
}

// enrichOne 用 NVD CVE 数据 UPDATE 现有 vulnerabilities.cve_id 匹配行。
// 仅补全空字段，不覆盖 OS Advisory 已填的 component/fixed_version 等精确数据。
func (e *nvdMetadataEnricher) enrichOne(cve *nvdAPICVE) int64 {
	if cve == nil || cve.ID == "" {
		return 0
	}

	description := extractDescription(cve.Descriptions)
	cvssScore, cvssVector, severity := extractCVSS(cve.Metrics)
	cweID := extractCWE(cve.Weaknesses)
	refURL := extractAdvisoryRef(cve.References)

	updates := map[string]any{}
	if description != "" {
		// 仅当现有 description 为空或太短（< 50 字）才覆盖（OS Advisory 套话替换）
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
	if refURL != "" {
		updates["reference_url"] = refURL
	}
	if len(updates) == 0 {
		return 0
	}

	result := e.db.Table("vulnerabilities").
		Where("cve_id = ? AND (description IS NULL OR description = '' OR LENGTH(description) < 50 OR cvss_score = 0)", cve.ID).
		Updates(updates)
	if result.Error != nil {
		e.logger.Warn("NVD 元数据 UPDATE 失败",
			zap.String("cve", cve.ID), zap.Error(result.Error))
		return 0
	}
	return result.RowsAffected
}

func extractDescription(descs []nvdAPIDesc) string {
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

func extractCVSS(metrics nvdAPIMetrics) (float64, string, string) {
	if len(metrics.CVSSMetricV31) > 0 {
		m := metrics.CVSSMetricV31[0].CVSSData
		return m.BaseScore, m.VectorString, normalizeSeverityLabel(m.BaseSeverity)
	}
	if len(metrics.CVSSMetricV30) > 0 {
		m := metrics.CVSSMetricV30[0].CVSSData
		return m.BaseScore, m.VectorString, normalizeSeverityLabel(m.BaseSeverity)
	}
	return 0, "", ""
}

func normalizeSeverityLabel(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return ""
}

func extractCWE(weaknesses []nvdAPIWeakness) string {
	for _, w := range weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				return d.Value
			}
		}
	}
	return ""
}

func extractAdvisoryRef(refs []nvdAPIRef) string {
	for _, r := range refs {
		for _, tag := range r.Tags {
			if tag == "Vendor Advisory" || tag == "Third Party Advisory" {
				return r.URL
			}
		}
	}
	if len(refs) > 0 {
		return refs[0].URL
	}
	return ""
}

// getEnvOr 取 env，缺省返默认。
func getEnvOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
