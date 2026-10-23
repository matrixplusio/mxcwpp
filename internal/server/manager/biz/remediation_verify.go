package biz

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// RemediationVerifier 修复验证器
type RemediationVerifier struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewRemediationVerifier 创建修复验证器
func NewRemediationVerifier(db *gorm.DB, logger *zap.Logger) *RemediationVerifier {
	return &RemediationVerifier{db: db, logger: logger}
}

// VerifyResult 验证结果
type VerifyResult struct {
	VulnID         uint   `json:"vulnId"`
	HostID         string `json:"hostId"`
	Verified       bool   `json:"verified"`
	CurrentVersion string `json:"currentVersion"`
	FixedVersion   string `json:"fixedVersion"`
	Message        string `json:"message"`
}

// VerifyHost 验证指定主机上的漏洞是否已修复
// 通过比对 software 表中的当前版本与漏洞的 fixed_version
func (v *RemediationVerifier) VerifyHost(vulnID uint, hostID string) (*VerifyResult, error) {
	// 查询漏洞信息
	var vuln model.Vulnerability
	if err := v.db.First(&vuln, vulnID).Error; err != nil {
		return nil, fmt.Errorf("漏洞不存在: %w", err)
	}

	result := &VerifyResult{
		VulnID:       vulnID,
		HostID:       hostID,
		FixedVersion: vuln.FixedVersion,
	}

	if vuln.FixedVersion == "" {
		result.Message = "无已知修复版本，无法自动验证"
		return result, nil
	}

	// 查询主机上该组件的当前版本
	var software struct {
		Version     string    `gorm:"column:version"`
		CollectedAt time.Time `gorm:"column:collected_at"`
	}
	err := v.db.Table("software").
		Select("version, collected_at").
		Where("host_id = ? AND name = ?", hostID, vuln.Component).
		Order("collected_at DESC").
		Limit(1).
		Scan(&software).Error

	if err != nil || software.Version == "" {
		result.Message = "未找到该组件的安装信息，可能已卸载或主机未上报软件清单"
		return result, nil
	}

	result.CurrentVersion = software.Version

	// 检查数据时效性：如果软件信息超过 1 小时未采集，提示可能不准确
	if time.Since(software.CollectedAt) > time.Hour {
		result.Message = fmt.Sprintf("注意：软件清单数据较旧（最后采集于 %s），验证结果可能不准确，建议等待 Agent 上报最新数据后重试",
			software.CollectedAt.Format("2006-01-02 15:04"))
	}

	// 比对版本：当前版本 >= 修复版本 则视为已修复
	if compareVersionStrings(software.Version, vuln.FixedVersion) >= 0 {
		result.Verified = true
		result.Message = fmt.Sprintf("验证通过：当前版本 %s >= 修复版本 %s", software.Version, vuln.FixedVersion)

		// 自动更新状态
		now := model.Now()
		v.db.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND host_id = ? AND status = ?", vulnID, hostID, "unpatched").
			Updates(map[string]any{
				"status":          "patched",
				"patched_at":      now,
				"current_version": software.Version,
			})

		// 更新漏洞主表
		var patchedCount int64
		v.db.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", vulnID, "patched").
			Count(&patchedCount)

		var unpatchedCount int64
		v.db.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", vulnID, "unpatched").
			Count(&unpatchedCount)

		updates := map[string]any{"patched_hosts": patchedCount}
		if unpatchedCount == 0 {
			updates["status"] = "patched"
			updates["patched_at"] = now
		}
		v.db.Model(&model.Vulnerability{}).Where("id = ?", vulnID).Updates(updates)
	} else {
		result.Message = fmt.Sprintf("验证未通过：当前版本 %s < 修复版本 %s", software.Version, vuln.FixedVersion)
	}

	return result, nil
}

// VerifyTask 验证修复任务关联的漏洞
func (v *RemediationVerifier) VerifyTask(taskID uint) (*VerifyResult, error) {
	var task model.RemediationTask
	if err := v.db.First(&task, taskID).Error; err != nil {
		return nil, fmt.Errorf("任务不存在: %w", err)
	}

	if task.Status != "success" {
		return nil, fmt.Errorf("任务尚未执行成功，无法验证")
	}

	return v.VerifyHost(task.VulnID, task.HostID)
}

// BatchVerify 批量验证漏洞的所有受影响主机
func (v *RemediationVerifier) BatchVerify(vulnID uint) ([]VerifyResult, error) {
	var hostVulns []model.HostVulnerability
	v.db.Where("vuln_id = ? AND status = ?", vulnID, "unpatched").Find(&hostVulns)

	if len(hostVulns) == 0 {
		return nil, nil
	}

	var results []VerifyResult
	for _, hv := range hostVulns {
		result, err := v.VerifyHost(vulnID, hv.HostID)
		if err != nil {
			v.logger.Warn("验证主机失败",
				zap.Uint("vuln_id", vulnID),
				zap.String("host_id", hv.HostID),
				zap.Error(err))
			continue
		}
		results = append(results, *result)
	}

	return results, nil
}

// compareVersionStrings 版本比较（支持 epoch:version-release 格式）
// 比较顺序：epoch → version → release（与 RPM/DEB 标准一致）
func compareVersionStrings(v1, v2 string) int {
	// 提取 epoch（默认 0）
	e1, v1 := splitEpoch(v1)
	e2, v2 := splitEpoch(v2)
	if e1 != e2 {
		if e1 < e2 {
			return -1
		}
		return 1
	}

	// 分离 version 和 release（如 1.2.3-4.el7）
	ver1, rel1 := splitRelease(v1)
	ver2, rel2 := splitRelease(v2)

	// 比较主版本号
	if cmp := compareSegments(ver1, ver2); cmp != 0 {
		return cmp
	}

	// 主版本相同时比较 release（有 release 的视为更新）
	if rel1 == "" && rel2 == "" {
		return 0
	}
	if rel1 == "" {
		return -1
	}
	if rel2 == "" {
		return 1
	}
	return compareSegments(rel1, rel2)
}

// splitEpoch 提取 epoch 部分（如 "1:2.3.4" → epoch=1, rest="2.3.4"）
func splitEpoch(v string) (int, string) {
	if idx := strings.Index(v, ":"); idx >= 0 {
		return parseVersionPart(v[:idx]), v[idx+1:]
	}
	return 0, v
}

// splitRelease 分离 version 和 release（如 "1.2.3-4.el7" → "1.2.3", "4.el7"）
func splitRelease(v string) (string, string) {
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		return v[:idx], v[idx+1:]
	}
	return v, ""
}

// compareSegments 按点号分割后逐段比较版本号
func compareSegments(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			n1 = parseVersionPart(parts1[i])
		}
		if i < len(parts2) {
			n2 = parseVersionPart(parts2[i])
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}

// parseVersionPart 解析版本号段（提取前导数字）
func parseVersionPart(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}
