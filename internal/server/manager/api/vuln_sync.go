package api

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz/advisory"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// VulnSyncHandler 漏洞数据多源同步 admin API。
type VulnSyncHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewVulnSyncHandler 构造默认 handler。
func NewVulnSyncHandler(db *gorm.DB, logger *zap.Logger) *VulnSyncHandler {
	return &VulnSyncHandler{db: db, logger: logger}
}

// SyncAdvisories POST /api/v1/vulnerabilities/advisory-sync
//
// 触发 advisory.Coordinator 拉取 RHSA/Rocky/USN/Debian/OSV，按 OS 精确匹配
// 入库 + soft-update 现有 host_vulnerabilities。
//
// 入参（可选）：
//
//	{ "since": "2024-01-01", "truncate": false }
//
// truncate=true 时先清空 vulnerabilities + host_vulnerabilities（仅 dev 验收使用）。
func (h *VulnSyncHandler) SyncAdvisories(c *gin.Context) {
	var req struct {
		Since    string `json:"since"`
		Truncate bool   `json:"truncate"`
	}
	_ = c.ShouldBindJSON(&req)

	since := time.Time{}
	if req.Since != "" {
		if t, err := time.Parse("2006-01-02", req.Since); err == nil {
			since = t
		}
	}

	if req.Truncate {
		h.logger.Warn("truncate 模式：清空 vulnerabilities + host_vulnerabilities")
		// 先禁 FK 再 truncate（child→parent 顺序避免 FK 约束阻挡）
		if err := h.db.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
			InternalError(c, "禁 FK 失败: "+err.Error())
			return
		}
		defer func() { _ = h.db.Exec("SET FOREIGN_KEY_CHECKS = 1").Error }()
		if err := h.db.Exec("TRUNCATE TABLE host_vulnerabilities").Error; err != nil {
			InternalError(c, "truncate host_vulnerabilities 失败: "+err.Error())
			return
		}
		if err := h.db.Exec("TRUNCATE TABLE vulnerabilities").Error; err != nil {
			InternalError(c, "truncate vulnerabilities 失败: "+err.Error())
			return
		}
	}

	// 取 host 软件清单作为 matcher 输入
	hosts, err := h.loadHostSoftware()
	if err != nil {
		InternalError(c, "加载 host 软件清单失败: "+err.Error())
		return
	}

	coord := advisory.NewCoordinator(h.db, h.logger)
	// 90min：Rocky-Apollo / Debian-tracker 全量需 10-20min 各，sequential fetch
	// 累计可超 30min，扩到 90min 留余量。生产 cron 同步同样配置。
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()
	vulnCount, hostVulnCount, err := coord.Sync(ctx, since, hosts)
	if err != nil {
		InternalError(c, "coordinator sync 失败: "+err.Error())
		return
	}

	Success(c, gin.H{
		"vuln_count":      vulnCount,
		"host_vuln_count": hostVulnCount,
		"host_count":      len(hosts),
		"since":           req.Since,
		"truncated":       req.Truncate,
	})
}

// loadHostSoftware 从 hosts + 各 software 表 join 出 advisory.HostSoftware 清单。
//
// 当前实现：从 collector 上报的 host_packages 表（如有）；否则从 hosts.os_family/os_version
// 推断空 pkg 清单（仅 OS 元信息可参与 match 但无 pkg 实际比对）。
//
// 完整版应集成 host_packages 表（collector plugin 上报 rpm -qa / dpkg -l 结果）。
func (h *VulnSyncHandler) loadHostSoftware() ([]advisory.HostSoftware, error) {
	type hostRow struct {
		HostID    string
		Hostname  string
		OSFamily  string
		OSVersion string
		Arch      string
	}
	var rows []hostRow
	if err := h.db.Model(&model.Host{}).
		Select("host_id, hostname, os_family, os_version, arch").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]advisory.HostSoftware, 0, len(rows))
	for _, r := range rows {
		out = append(out, advisory.HostSoftware{
			HostID:   r.HostID,
			Hostname: r.Hostname,
			OSFamily: r.OSFamily,
			OSVer:    r.OSVersion,
			OSMajor:  osMajorVersion(r.OSVersion),
			Arch:     r.Arch,
		})
	}
	return out, nil
}

// osMajorVersion 提取 OS 主版本号（"9.4" → "9"）。
func osMajorVersion(ver string) string {
	for i, c := range ver {
		if c == '.' {
			return ver[:i]
		}
	}
	return ver
}
