package biz

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ImageScanner 容器镜像扫描编排器：创建扫描记录 + 入队 scan_jobs，
// 实际 trivy 扫描由独立 scanner 服务消费执行（manager 不跑 trivy）。
type ImageScanner struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewImageScanner 创建镜像扫描编排器
func NewImageScanner(db *gorm.DB, logger *zap.Logger) *ImageScanner {
	return &ImageScanner{db: db, logger: logger}
}

// EnqueueScan 创建 pending 扫描记录 + 入队扫描任务，返回扫描记录（异步，结果由 scanner 服务回填）。
func (s *ImageScanner) EnqueueScan(image, source string, registryID *uint) (*model.ImageScan, error) {
	scan := &model.ImageScan{Image: image, Status: "pending", Source: source}
	job := &model.ScanJob{Image: image, Source: source, RegistryID: registryID, Status: model.ScanJobPending}

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if e := tx.Create(scan).Error; e != nil {
			return e
		}
		job.ResultScanID = scan.ID
		return tx.Create(job).Error
	}); err != nil {
		return nil, fmt.Errorf("入队扫描任务失败: %w", err)
	}
	s.logger.Info("镜像扫描已入队", zap.String("image", image), zap.String("source", source), zap.Uint("scanId", scan.ID))
	return scan, nil
}

// ScanImage 入队单个容器镜像扫描（手动）
func (s *ImageScanner) ScanImage(image string) (*model.ImageScan, error) {
	return s.EnqueueScan(image, "manual", nil)
}

// GetScanHistory 获取扫描历史（可选按集群过滤）
func (s *ImageScanner) GetScanHistory(page, pageSize int, clusterID *uint) ([]model.ImageScan, int64, error) {
	query := s.db.Model(&model.ImageScan{})
	if clusterID != nil {
		query = query.Where("cluster_id = ?", *clusterID)
	}

	var total int64
	query.Count(&total)

	var scans []model.ImageScan
	err := query.Order("created_at DESC").
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

// ScanRegistry 列出 Registry 中所有镜像并逐个入队扫描
func (s *ImageScanner) ScanRegistry(registryID uint) error {
	var registry model.ImageRegistry
	if err := s.db.First(&registry, registryID).Error; err != nil {
		return fmt.Errorf("Registry 不存在: %w", err)
	}

	s.logger.Info("开始扫描 Registry", zap.String("name", registry.Name), zap.String("url", registry.URL))

	images, err := s.listRegistryImages(&registry)
	if err != nil {
		return fmt.Errorf("获取镜像列表失败: %w", err)
	}

	now := model.Now()
	s.db.Model(&registry).Updates(map[string]any{"image_count": len(images), "last_sync_at": now})

	rid := registryID
	for _, image := range images {
		if _, e := s.EnqueueScan(image, "registry", &rid); e != nil {
			s.logger.Warn("入队镜像扫描失败", zap.String("image", image), zap.Error(e))
		}
	}

	s.logger.Info("Registry 镜像已全部入队", zap.String("name", registry.Name), zap.Int("images", len(images)))
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
