package biz

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ImageScanner 容器镜像漏洞扫描器（基于 Trivy CLI）
type ImageScanner struct {
	db        *gorm.DB
	logger    *zap.Logger
	trivyPath string
}

// NewImageScanner 创建镜像扫描器
func NewImageScanner(db *gorm.DB, logger *zap.Logger) *ImageScanner {
	trivyPath := "trivy"
	// 尝试从配置读取自定义路径
	var configPath string
	if err := db.Table("system_configs").
		Select("value").
		Where("`key` = ?", "trivy_path").
		Scan(&configPath).Error; err == nil && configPath != "" {
		trivyPath = configPath
	}

	return &ImageScanner{
		db:        db,
		logger:    logger,
		trivyPath: trivyPath,
	}
}

// ScanImage 扫描单个容器镜像（公开镜像或已配置 Docker 凭据的场景）
func (s *ImageScanner) ScanImage(image string) (*model.ImageScan, error) {
	return s.ScanImageWithAuth(image, "", "")
}

// ScanImageWithAuth 扫描容器镜像（支持 Registry 认证）
func (s *ImageScanner) ScanImageWithAuth(image, username, password string) (*model.ImageScan, error) {
	s.logger.Info("开始扫描容器镜像", zap.String("image", image))

	// 创建扫描记录
	scan := &model.ImageScan{
		Image:  image,
		Status: "scanning",
	}
	if err := s.db.Create(scan).Error; err != nil {
		return nil, fmt.Errorf("创建扫描记录失败: %w", err)
	}

	// 检查 Trivy 是否可用
	if _, err := exec.LookPath(s.trivyPath); err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = "trivy 未安装或路径不正确"
		s.db.Save(scan)
		return scan, fmt.Errorf("trivy 不可用: %w", err)
	}

	// 执行 Trivy 扫描
	output, err := s.runTrivy(image, username, password)
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = err.Error()
		s.db.Save(scan)
		return scan, err
	}

	// 解析结果
	vulns, trivyMeta, err := s.parseTrivyOutput(output)
	if err != nil {
		scan.Status = "failed"
		scan.ErrorMsg = "解析 Trivy 输出失败: " + err.Error()
		s.db.Save(scan)
		return scan, err
	}

	// 更新扫描记录
	now := model.Now()
	scan.Status = "done"
	scan.ScannedAt = &now
	scan.TotalVulns = len(vulns)
	scan.OS = trivyMeta.os
	scan.Digest = trivyMeta.digest

	critical, high := 0, 0
	for _, v := range vulns {
		switch v.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		}
	}
	scan.CriticalCnt = critical
	scan.HighCnt = high
	s.db.Save(scan)

	// 批量写入镜像漏洞
	for i := range vulns {
		vulns[i].ImageScanID = scan.ID
		// 尝试关联已有漏洞记录
		if vulns[i].CveID != "" {
			var vulnID uint
			s.db.Table("vulnerabilities").Select("id").Where("cve_id = ?", vulns[i].CveID).Scan(&vulnID)
			if vulnID > 0 {
				vulns[i].VulnID = &vulnID
			}
		}
	}
	if len(vulns) > 0 {
		s.db.CreateInBatches(vulns, 100)
	}

	s.logger.Info("镜像扫描完成",
		zap.String("image", image),
		zap.Int("total", len(vulns)),
		zap.Int("critical", critical),
		zap.Int("high", high))

	return scan, nil
}

// runTrivy 执行 Trivy CLI
func (s *ImageScanner) runTrivy(image, username, password string) ([]byte, error) {
	args := []string{
		"image",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--quiet",
	}
	if username != "" {
		args = append(args, "--username", username, "--password", password)
	}
	args = append(args, image)

	cmd := exec.Command(s.trivyPath, args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy 执行失败 (exit %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("trivy 执行失败: %w", err)
	}

	return output, nil
}

// trivyOutput Trivy JSON 输出结构
type trivyOutput struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      trivyMetadata `json:"Metadata"`
	Results       []trivyResult `json:"Results"`
}

type trivyMetadata struct {
	OS          *trivyOS `json:"OS"`
	RepoDigests []string `json:"RepoDigests"`
}

type trivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

type trivyMeta struct {
	os     string
	digest string
}

// parseTrivyOutput 解析 Trivy JSON 输出
func (s *ImageScanner) parseTrivyOutput(output []byte) ([]model.ImageVulnerability, trivyMeta, error) {
	var report trivyOutput
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, trivyMeta{}, fmt.Errorf("解析 JSON 失败: %w", err)
	}

	meta := trivyMeta{}
	if report.Metadata.OS != nil {
		meta.os = report.Metadata.OS.Family + " " + report.Metadata.OS.Name
	}
	if len(report.Metadata.RepoDigests) > 0 {
		meta.digest = report.Metadata.RepoDigests[0]
	}

	var vulns []model.ImageVulnerability
	seen := make(map[string]struct{})

	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			// 同一 CVE + 同一包只记录一次
			key := v.VulnerabilityID + "|" + v.PkgName
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			vulns = append(vulns, model.ImageVulnerability{
				CveID:        v.VulnerabilityID,
				Package:      v.PkgName,
				Version:      v.InstalledVersion,
				FixedVersion: v.FixedVersion,
				Severity:     v.Severity,
				Title:        v.Title,
			})
		}
	}

	return vulns, meta, nil
}

// GetScanHistory 获取扫描历史
func (s *ImageScanner) GetScanHistory(page, pageSize int) ([]model.ImageScan, int64, error) {
	var total int64
	s.db.Model(&model.ImageScan{}).Count(&total)

	var scans []model.ImageScan
	err := s.db.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&scans).Error

	return scans, total, err
}

// GetScanVulns 获取扫描的漏洞列表
func (s *ImageScanner) GetScanVulns(scanID uint) ([]model.ImageVulnerability, error) {
	var vulns []model.ImageVulnerability
	err := s.db.Where("image_scan_id = ?", scanID).Find(&vulns).Error
	return vulns, err
}

// GetScanByID 获取扫描详情
func (s *ImageScanner) GetScanByID(id uint) (*model.ImageScan, error) {
	var scan model.ImageScan
	if err := s.db.First(&scan, id).Error; err != nil {
		return nil, err
	}
	return &scan, nil
}

// ScanRegistry 扫描 Registry 中的所有镜像
func (s *ImageScanner) ScanRegistry(registryID uint) error {
	var registry model.ImageRegistry
	if err := s.db.First(&registry, registryID).Error; err != nil {
		return fmt.Errorf("Registry 不存在: %w", err)
	}

	s.logger.Info("开始扫描 Registry", zap.String("name", registry.Name), zap.String("url", registry.URL))

	// 获取镜像列表
	images, err := s.listRegistryImages(&registry)
	if err != nil {
		return fmt.Errorf("获取镜像列表失败: %w", err)
	}

	s.logger.Info("Registry 镜像列表", zap.Int("count", len(images)))

	// 更新 Registry 信息
	now := model.Now()
	s.db.Model(&registry).Updates(map[string]any{
		"image_count":  len(images),
		"last_sync_at": now,
	})

	// 逐个扫描（并发控制，最多 3 个并行），传递 Registry 凭据
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup

	for _, image := range images {
		sem <- struct{}{}
		wg.Add(1)
		go func(img string) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := s.ScanImageWithAuth(img, registry.Username, registry.Password); err != nil {
				s.logger.Warn("镜像扫描失败", zap.String("image", img), zap.Error(err))
			}
		}(image)
	}
	wg.Wait()

	s.logger.Info("Registry 扫描完成", zap.String("name", registry.Name), zap.Int("images", len(images)))
	return nil
}

// listRegistryImages 通过 Docker Registry V2 API 获取镜像列表
func (s *ImageScanner) listRegistryImages(registry *model.ImageRegistry) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	if registry.Insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// 1. 获取 catalog
	catalogURL := strings.TrimRight(registry.URL, "/") + "/v2/_catalog"
	req, _ := http.NewRequest("GET", catalogURL, nil)
	if registry.Username != "" {
		req.SetBasicAuth(registry.Username, registry.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 catalog 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog 响应状态码: %d", resp.StatusCode)
	}

	var catalog struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("解析 catalog 失败: %w", err)
	}

	// 2. 获取每个 repo 的 tags
	var images []string
	for _, repo := range catalog.Repositories {
		tagsURL := strings.TrimRight(registry.URL, "/") + "/v2/" + repo + "/tags/list"
		tagReq, _ := http.NewRequest("GET", tagsURL, nil)
		if registry.Username != "" {
			tagReq.SetBasicAuth(registry.Username, registry.Password)
		}

		tagResp, err := client.Do(tagReq)
		if err != nil {
			s.logger.Warn("获取 tags 失败", zap.String("repo", repo), zap.Error(err))
			continue
		}

		var tagList struct {
			Tags []string `json:"tags"`
		}
		if err := json.NewDecoder(tagResp.Body).Decode(&tagList); err != nil {
			s.logger.Warn("解析 tags 失败", zap.String("repo", repo), zap.Error(err))
			tagResp.Body.Close()
			continue
		}
		tagResp.Body.Close()

		registryHost := strings.TrimPrefix(strings.TrimPrefix(registry.URL, "https://"), "http://")
		registryHost = strings.TrimRight(registryHost, "/")
		for _, tag := range tagList.Tags {
			images = append(images, registryHost+"/"+repo+":"+tag)
		}
	}

	return images, nil
}

// init 确保 time 包被引用（parseTrivyOutput 中未直接使用，但 model.Now 依赖）
var _ = time.Now
