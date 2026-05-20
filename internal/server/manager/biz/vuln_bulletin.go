package biz

import (
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// VulnBulletinService 漏洞通报服务
type VulnBulletinService struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewVulnBulletinService 创建漏洞通报服务
func NewVulnBulletinService(db *gorm.DB, logger *zap.Logger) *VulnBulletinService {
	return &VulnBulletinService{db: db, logger: logger}
}

// GetConfig 获取通报配置
func (s *VulnBulletinService) GetConfig() model.VulnBulletinConfig {
	cfg := model.DefaultVulnBulletinConfig()

	var sc model.SystemConfig
	if err := s.db.Where("`key` = ? AND category = ?", "vuln_bulletin_config", "vulnerability").
		First(&sc).Error; err != nil {
		return cfg
	}
	if sc.Value != "" {
		_ = json.Unmarshal([]byte(sc.Value), &cfg)
	}
	return cfg
}

// SaveConfig 保存通报配置
func (s *VulnBulletinService) SaveConfig(cfg model.VulnBulletinConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	sc := model.SystemConfig{
		Key:      "vuln_bulletin_config",
		Category: "vulnerability",
		Value:    string(data),
	}
	return s.db.Where("`key` = ? AND category = ?", sc.Key, sc.Category).
		Assign(model.SystemConfig{Value: sc.Value}).
		FirstOrCreate(&sc).Error
}

// TryCreateBulletin 尝试为漏洞创建通报（含去重、分级判断、SLA 设置）
// 返回创建的通报（nil 表示不需要创建）
func (s *VulnBulletinService) TryCreateBulletin(vuln *model.Vulnerability) *model.VulnBulletin {
	cfg := s.GetConfig()
	if !cfg.Enabled || !cfg.AutoCreate {
		return nil
	}

	// 漏洞已被忽略，不创建通报
	if vuln.Status == "ignored" {
		return nil
	}

	// 去重：检查是否已有活跃通报（pending/notified/acknowledged）
	var existing model.VulnBulletin
	if err := s.db.Where("cve_id = ? AND status IN ?", vuln.CveID,
		[]string{model.BulletinStatusPending, model.BulletinStatusNotified, model.BulletinStatusAcknowledged}).
		First(&existing).Error; err == nil {
		// 已有活跃通报，更新影响资产数
		var affected int64
		s.db.Model(&model.HostVulnerability{}).Where("vuln_id = ? AND status = ?", vuln.ID, "unpatched").Count(&affected)
		if int(affected) != existing.AffectedAssets {
			s.db.Model(&existing).Update("affected_assets", int(affected))
		}
		return nil
	}

	// 计算分级
	priority, factors := ClassifyBulletinPriority(vuln)

	// 检查该优先级是否在启用列表中
	if !cfg.IsPriorityEnabled(priority) {
		return nil
	}

	// 统计影响资产数
	var affectedCount int64
	s.db.Model(&model.HostVulnerability{}).Where("vuln_id = ? AND status = ?", vuln.ID, "unpatched").Count(&affectedCount)

	// 生成通报编号
	bulletinNo := s.generateBulletinNo()

	// 计算 SLA 截止时间
	now := time.Now()
	ackDeadline := model.LocalTime(now.Add(time.Duration(cfg.GetAckHours(priority)) * time.Hour))
	resolveDeadline := model.LocalTime(now.Add(time.Duration(cfg.GetResolveHours(priority)) * time.Hour))

	// 生成修复建议
	fixSuggestion := ""
	if vuln.FixedVersion != "" {
		fixSuggestion = fmt.Sprintf("升级 %s 至 %s 及以上版本", vuln.Component, vuln.FixedVersion)
	}

	bulletin := &model.VulnBulletin{
		BulletinNo:      bulletinNo,
		VulnID:          vuln.ID,
		CveID:           vuln.CveID,
		Priority:        priority,
		PriorityFactors: factors,

		// 漏洞快照
		Component:    vuln.Component,
		Severity:     vuln.Severity,
		CvssScore:    vuln.CvssScore,
		CvssVector:   vuln.CvssVector,
		VulnType:     vuln.VulnType,
		AttackVector: vuln.AttackVector,
		Description:  vuln.Description,

		// 影响范围
		AffectedAssets:   int(affectedCount),
		AffectedVersions: vuln.AffectedVersions,

		// 修复信息
		FixedVersion:   vuln.FixedVersion,
		FixSuggestion:  fixSuggestion,
		PatchAvailable: vuln.PatchAvailable,

		// 威胁情报
		Source:     vuln.Source,
		HasExploit: vuln.HasExploit,
		InKEV:      vuln.InKEV,
		EpssScore:  vuln.EpssScore,
		ExploitRef: vuln.ExploitRef,

		// 生命周期
		Status: model.BulletinStatusPending,

		// SLA
		SLAAckDeadline:     &ackDeadline,
		SLAResolveDeadline: &resolveDeadline,
	}

	if err := s.db.Create(bulletin).Error; err != nil {
		s.logger.Error("创建漏洞通报失败", zap.String("cve_id", vuln.CveID), zap.Error(err))
		return nil
	}

	s.logger.Info("创建漏洞通报",
		zap.String("bulletin_no", bulletinNo),
		zap.String("cve_id", vuln.CveID),
		zap.String("priority", priority),
		zap.String("component", vuln.Component),
		zap.Int64("affected_assets", affectedCount),
	)

	return bulletin
}

// generateBulletinNo 生成通报编号 MX-YYYY-NNNN
func (s *VulnBulletinService) generateBulletinNo() string {
	year := time.Now().Year()
	prefix := fmt.Sprintf("MX-%d-", year)

	// 查询当年最大编号
	var maxNo string
	s.db.Model(&model.VulnBulletin{}).
		Where("bulletin_no LIKE ?", prefix+"%").
		Order("bulletin_no DESC").
		Limit(1).
		Pluck("bulletin_no", &maxNo)

	seq := 1
	if maxNo != "" {
		// 解析序号
		var n int
		if _, err := fmt.Sscanf(maxNo, prefix+"%d", &n); err == nil {
			seq = n + 1
		}
	}

	return fmt.Sprintf("%s%04d", prefix, seq)
}

// Acknowledge 确认通报
func (s *VulnBulletinService) Acknowledge(id uint, username string) error {
	now := model.Now()
	return s.db.Model(&model.VulnBulletin{}).Where("id = ? AND status IN ?", id,
		[]string{model.BulletinStatusPending, model.BulletinStatusNotified}).
		Updates(map[string]any{
			"status":          model.BulletinStatusAcknowledged,
			"acknowledged_at": &now,
			"acknowledged_by": username,
		}).Error
}

// Resolve 修复通报
func (s *VulnBulletinService) Resolve(id uint, username, comment string) error {
	now := model.Now()
	return s.db.Model(&model.VulnBulletin{}).Where("id = ? AND status IN ?", id,
		[]string{model.BulletinStatusPending, model.BulletinStatusNotified, model.BulletinStatusAcknowledged}).
		Updates(map[string]any{
			"status":          model.BulletinStatusResolved,
			"resolved_at":     &now,
			"resolved_by":     username,
			"resolve_comment": comment,
		}).Error
}

// Ignore 忽略通报
func (s *VulnBulletinService) Ignore(id uint, username, reason string) error {
	now := model.Now()
	return s.db.Model(&model.VulnBulletin{}).Where("id = ? AND status IN ?", id,
		[]string{model.BulletinStatusPending, model.BulletinStatusNotified, model.BulletinStatusAcknowledged}).
		Updates(map[string]any{
			"status":        model.BulletinStatusIgnored,
			"ignored_at":    &now,
			"ignored_by":    username,
			"ignore_reason": reason,
		}).Error
}

// Reopen 重新打开通报
func (s *VulnBulletinService) Reopen(id uint) error {
	cfg := s.GetConfig()
	now := time.Now()
	ackDeadline := model.LocalTime(now.Add(time.Duration(cfg.P2AckHours) * time.Hour))
	resolveDeadline := model.LocalTime(now.Add(time.Duration(cfg.P2ResolveHours) * time.Hour))

	return s.db.Model(&model.VulnBulletin{}).Where("id = ? AND status IN ?", id,
		[]string{model.BulletinStatusIgnored, model.BulletinStatusResolved}).
		Updates(map[string]any{
			"status":               model.BulletinStatusPending,
			"sla_ack_deadline":     &ackDeadline,
			"sla_resolve_deadline": &resolveDeadline,
			"sla_breached":         false,
		}).Error
}

// BatchAction 批量操作
func (s *VulnBulletinService) BatchAction(ids []uint, action, username, reason string) error {
	for _, id := range ids {
		var err error
		switch action {
		case "acknowledge":
			err = s.Acknowledge(id, username)
		case "resolve":
			err = s.Resolve(id, username, reason)
		case "ignore":
			err = s.Ignore(id, username, reason)
		}
		if err != nil {
			s.logger.Warn("批量操作失败", zap.Uint("id", id), zap.String("action", action), zap.Error(err))
		}
	}
	return nil
}

// AutoResolvePatched 自动关闭所有主机已修复的通报
func (s *VulnBulletinService) AutoResolvePatched() {
	var bulletins []model.VulnBulletin
	s.db.Where("status IN ?", []string{
		model.BulletinStatusPending,
		model.BulletinStatusNotified,
		model.BulletinStatusAcknowledged,
	}).Find(&bulletins)

	for _, b := range bulletins {
		var unpatched int64
		s.db.Model(&model.HostVulnerability{}).
			Where("vuln_id = ? AND status = ?", b.VulnID, "unpatched").
			Count(&unpatched)
		if unpatched == 0 {
			now := model.Now()
			s.db.Model(&b).Updates(map[string]any{
				"status":          model.BulletinStatusResolved,
				"resolved_at":     &now,
				"resolved_by":     "system",
				"resolve_comment": "所有受影响资产已修复",
				"affected_assets": 0,
			})
			s.logger.Info("通报自动关闭（全部修复）", zap.String("bulletin_no", b.BulletinNo))
		}
	}
}

// CheckSLABreach 检查 SLA 超时
func (s *VulnBulletinService) CheckSLABreach() {
	now := time.Now()

	// 确认超时：pending/notified 且超过确认截止时间
	s.db.Model(&model.VulnBulletin{}).
		Where("sla_breached = ? AND status IN ? AND sla_ack_deadline < ?",
			false,
			[]string{model.BulletinStatusPending, model.BulletinStatusNotified},
			now).
		Update("sla_breached", true)

	// 修复超时：acknowledged 且超过修复截止时间
	s.db.Model(&model.VulnBulletin{}).
		Where("sla_breached = ? AND status = ? AND sla_resolve_deadline < ?",
			false,
			model.BulletinStatusAcknowledged,
			now).
		Update("sla_breached", true)
}

// GetStatistics 获取通报统计
func (s *VulnBulletinService) GetStatistics() map[string]any {
	type countRow struct {
		Key   string `gorm:"column:key"`
		Count int    `gorm:"column:count"`
	}

	// 按优先级统计
	var byPriority []countRow
	s.db.Model(&model.VulnBulletin{}).
		Select("priority as `key`, COUNT(*) as `count`").
		Group("priority").Scan(&byPriority)

	// 按状态统计
	var byStatus []countRow
	s.db.Model(&model.VulnBulletin{}).
		Select("status as `key`, COUNT(*) as `count`").
		Group("status").Scan(&byStatus)

	// SLA 超时数
	var slaBreached int64
	s.db.Model(&model.VulnBulletin{}).
		Where("sla_breached = ? AND status NOT IN ?", true,
			[]string{model.BulletinStatusResolved, model.BulletinStatusIgnored}).
		Count(&slaBreached)

	// 活跃通报数
	var activeCount int64
	s.db.Model(&model.VulnBulletin{}).
		Where("status IN ?", []string{
			model.BulletinStatusPending,
			model.BulletinStatusNotified,
			model.BulletinStatusAcknowledged,
		}).Count(&activeCount)

	priorityMap := make(map[string]int)
	for _, r := range byPriority {
		priorityMap[r.Key] = r.Count
	}
	statusMap := make(map[string]int)
	for _, r := range byStatus {
		statusMap[r.Key] = r.Count
	}

	return map[string]any{
		"active":       activeCount,
		"sla_breached": slaBreached,
		"by_priority":  priorityMap,
		"by_status":    statusMap,
	}
}
