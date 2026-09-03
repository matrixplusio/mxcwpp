// Package scanner 是独立镜像扫描服务的核心：从 scan_jobs 队列认领任务，
// 调用 trivy 扫描镜像，结果写回 image_scans / image_vulnerabilities。
// 与 manager 解耦（manager 只入队，不跑 trivy），可多副本水平扩展。
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Worker 扫描工作进程：轮询认领并执行扫描任务。
type Worker struct {
	db        *gorm.DB
	logger    *zap.Logger
	trivyPath string
	id        string // claimed_by 标识（区分多副本）
	interval  time.Duration
}

// NewWorker 创建扫描工作进程。
func NewWorker(db *gorm.DB, logger *zap.Logger, trivyPath, id string) *Worker {
	if trivyPath == "" {
		trivyPath = "trivy"
	}
	return &Worker{db: db, logger: logger, trivyPath: trivyPath, id: id, interval: 3 * time.Second}
}

// Run 启动认领-执行循环，直到 ctx 取消。
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("镜像扫描 worker 已启动", zap.String("id", w.id), zap.String("trivy", w.trivyPath))
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		// 连续认领，直到队列空，再等下一个 tick
		for w.claimAndProcess() {
			if ctx.Err() != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			w.logger.Info("镜像扫描 worker 已停止")
			return
		case <-ticker.C:
		}
	}
}

// claimAndProcess 原子认领一个 pending 任务并执行；返回是否认领到任务。
func (w *Worker) claimAndProcess() bool {
	var job model.ScanJob
	// 事务 + FOR UPDATE SKIP LOCKED，保证多副本并发安全
	err := w.db.Transaction(func(tx *gorm.DB) error {
		if e := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ?", model.ScanJobPending).
			Order("id").First(&job).Error; e != nil {
			return e
		}
		now := model.Now()
		return tx.Model(&job).Updates(map[string]any{
			"status":     model.ScanJobRunning,
			"claimed_by": w.id,
			"claimed_at": now,
			"attempt":    gorm.Expr("attempt + 1"),
		}).Error
	})
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			w.logger.Warn("认领扫描任务失败", zap.Error(err))
		}
		return false
	}

	w.process(&job)
	return true
}

// process 执行单个扫描任务：跑 trivy → 解析 → 更新 image_scans。
func (w *Worker) process(job *model.ScanJob) {
	w.logger.Info("开始扫描", zap.Uint("job", job.ID), zap.String("image", job.Image), zap.String("source", job.Source))

	// registry 认证：basic/acr 用 user/pass；gcr/gar 用 GCP SA JSON 凭证文件
	var username, password, gcpCredsPath string
	if job.RegistryID != nil {
		var reg model.ImageRegistry
		if e := w.db.First(&reg, *job.RegistryID).Error; e == nil {
			switch reg.Type {
			case "gcr", "gar":
				if reg.Password != "" {
					if f, ferr := os.CreateTemp("", "trivy-gcp-*.json"); ferr == nil {
						if _, werr := f.WriteString(reg.Password); werr == nil {
							gcpCredsPath = f.Name()
							defer os.Remove(gcpCredsPath)
						}
						f.Close()
					}
				}
			default: // basic / acr
				username, password = reg.Username, reg.Password
			}
		}
	}

	output, err := w.runTrivy(job.Image, username, password, gcpCredsPath)
	if err != nil {
		w.failJob(job, err.Error())
		return
	}
	vulns, meta, err := parseTrivyOutput(output)
	if err != nil {
		w.failJob(job, "解析 trivy 输出失败: "+err.Error())
		return
	}

	critical, high := 0, 0
	for _, v := range vulns {
		switch v.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		}
	}

	now := model.Now()
	if err := w.db.Transaction(func(tx *gorm.DB) error {
		// 更新扫描记录
		if e := tx.Model(&model.ImageScan{}).Where("id = ?", job.ResultScanID).Updates(map[string]any{
			"status":       "done",
			"scanned_at":   now,
			"total_vulns":  len(vulns),
			"critical_cnt": critical,
			"high_cnt":     high,
			"os":           meta.os,
			"digest":       meta.digest,
			"error_msg":    "",
		}).Error; e != nil {
			return e
		}
		// 重扫：先清旧漏洞再写
		if e := tx.Where("image_scan_id = ?", job.ResultScanID).Delete(&model.ImageVulnerability{}).Error; e != nil {
			return e
		}
		for i := range vulns {
			vulns[i].ImageScanID = job.ResultScanID
		}
		// 富化：关联到统一漏洞库(vulnsync)，叠加 EPSS/KEV/CNNVD/信创/confidence。
		// 引擎分开(trivy 负责镜像匹配)，数据层统一(共用我们的漏洞情报)。
		enrichVulnIDs(tx, vulns)
		if len(vulns) > 0 {
			if e := tx.CreateInBatches(vulns, 100).Error; e != nil {
				return e
			}
		}
		return tx.Model(job).Updates(map[string]any{"status": model.ScanJobDone, "error_msg": ""}).Error
	}); err != nil {
		w.failJob(job, "写入扫描结果失败: "+err.Error())
		return
	}

	w.logger.Info("扫描完成", zap.Uint("job", job.ID), zap.String("image", job.Image),
		zap.Int("total", len(vulns)), zap.Int("critical", critical), zap.Int("high", high))
}

// enrichVulnIDs 按 cve_id 批量关联统一漏洞库(vulnerabilities 表)的记录，
// 填充 VulnID，使镜像漏洞可叠加 EPSS/KEV/CNNVD/信创/confidence 等富化数据。
func enrichVulnIDs(db *gorm.DB, vulns []model.ImageVulnerability) {
	cves := make([]string, 0, len(vulns))
	seen := make(map[string]struct{})
	for _, v := range vulns {
		if v.CveID == "" {
			continue
		}
		if _, ok := seen[v.CveID]; ok {
			continue
		}
		seen[v.CveID] = struct{}{}
		cves = append(cves, v.CveID)
	}
	if len(cves) == 0 {
		return
	}
	type row struct {
		ID    uint
		CveID string
	}
	var rows []row
	if err := db.Table("vulnerabilities").Select("id, cve_id").Where("cve_id IN ?", cves).Scan(&rows).Error; err != nil {
		return
	}
	idByCve := make(map[string]uint, len(rows))
	for _, r := range rows {
		if _, ok := idByCve[r.CveID]; !ok {
			idByCve[r.CveID] = r.ID
		}
	}
	for i := range vulns {
		if id, ok := idByCve[vulns[i].CveID]; ok {
			vid := id
			vulns[i].VulnID = &vid
		}
	}
}

func (w *Worker) failJob(job *model.ScanJob, msg string) {
	w.logger.Warn("扫描失败", zap.Uint("job", job.ID), zap.String("image", job.Image), zap.String("err", msg))
	w.db.Model(job).Updates(map[string]any{"status": model.ScanJobFailed, "error_msg": msg})
	w.db.Model(&model.ImageScan{}).Where("id = ?", job.ResultScanID).Updates(map[string]any{"status": "failed", "error_msg": msg})
}

// runTrivy 执行 trivy CLI 扫描镜像。
func (w *Worker) runTrivy(image, username, password, gcpCredsPath string) ([]byte, error) {
	if _, err := exec.LookPath(w.trivyPath); err != nil {
		return nil, fmt.Errorf("trivy 未安装或路径不正确")
	}
	args := []string{"image", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM,LOW", "--quiet"}
	if username != "" {
		args = append(args, "--username", username, "--password", password)
	}
	args = append(args, image)

	cmd := exec.Command(w.trivyPath, args...)
	if gcpCredsPath != "" {
		cmd.Env = append(os.Environ(), "GOOGLE_APPLICATION_CREDENTIALS="+gcpCredsPath)
	}
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy 执行失败 (exit %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("trivy 执行失败: %w", err)
	}
	return output, nil
}

// ---- trivy JSON 解析 ----

type trivyOutput struct {
	Metadata trivyMetadata `json:"Metadata"`
	Results  []trivyResult `json:"Results"`
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

func parseTrivyOutput(output []byte) ([]model.ImageVulnerability, trivyMeta, error) {
	var report trivyOutput
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, trivyMeta{}, err
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
			key := v.VulnerabilityID + "|" + v.PkgName
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			vulns = append(vulns, model.ImageVulnerability{
				CveID: v.VulnerabilityID, Package: v.PkgName, Version: v.InstalledVersion,
				FixedVersion: v.FixedVersion, Severity: v.Severity, Title: v.Title,
			})
		}
	}
	return vulns, meta, nil
}
