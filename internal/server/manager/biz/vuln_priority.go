package biz

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// 优先级评分权重（默认值）
const (
	defaultWeightCVSS     = 0.35
	defaultWeightExploit  = 0.30
	defaultWeightExposure = 0.20
	defaultWeightPatch    = 0.15
)

// PriorityCalculator 漏洞优先级计算器
type PriorityCalculator struct {
	db     *gorm.DB
	logger *zap.Logger
	// 权重可配置
	WeightCVSS     float64
	WeightExploit  float64
	WeightExposure float64
	WeightPatch    float64
}

// NewPriorityCalculator 创建优先级计算器
func NewPriorityCalculator(db *gorm.DB, logger *zap.Logger) *PriorityCalculator {
	return &PriorityCalculator{
		db:             db,
		logger:         logger,
		WeightCVSS:     defaultWeightCVSS,
		WeightExploit:  defaultWeightExploit,
		WeightExposure: defaultWeightExposure,
		WeightPatch:    defaultWeightPatch,
	}
}

// RecalculateAll 重新计算所有 unpatched 漏洞的优先级评分
func (p *PriorityCalculator) RecalculateAll() error {
	p.logger.Info("开始批量重算漏洞优先级")

	// 查询总主机数（用于暴露面计算）
	var totalHosts int64
	if err := p.db.Table("hosts").Where("status = ?", "online").Count(&totalHosts).Error; err != nil {
		return fmt.Errorf("查询主机总数失败: %w", err)
	}
	if totalHosts == 0 {
		totalHosts = 1 // 避免除零
	}

	// 查询所有 unpatched 漏洞的 ID
	var vulnIDs []uint
	if err := p.db.Table("vulnerabilities").
		Select("id").
		Where("status = ?", "unpatched").
		Pluck("id", &vulnIDs).Error; err != nil {
		return fmt.Errorf("查询未修复漏洞失败: %w", err)
	}

	p.logger.Info("需要计算优先级的漏洞数", zap.Int("count", len(vulnIDs)))

	// 分批处理
	batchSize := 100
	updated := 0
	for i := 0; i < len(vulnIDs); i += batchSize {
		end := min(i+batchSize, len(vulnIDs))
		batch := vulnIDs[i:end]

		if err := p.recalculateBatch(batch, totalHosts); err != nil {
			p.logger.Warn("批量计算优先级失败", zap.Error(err))
		} else {
			updated += len(batch)
		}
	}

	p.logger.Info("漏洞优先级计算完成", zap.Int("updated", updated))
	return nil
}

// vulnScoreRow 用于批量查询漏洞评分所需数据
type vulnScoreRow struct {
	ID            uint    `gorm:"column:id"`
	CvssScore     float64 `gorm:"column:cvss_score"`
	HasExploit    bool    `gorm:"column:has_exploit"`
	InKEV         bool    `gorm:"column:in_kev"`
	AffectedHosts int     `gorm:"column:affected_hosts"`
	FixedVersion  string  `gorm:"column:fixed_version"`
}

// recalculateBatch 批量计算一批漏洞的优先级
func (p *PriorityCalculator) recalculateBatch(vulnIDs []uint, totalHosts int64) error {
	var rows []vulnScoreRow
	if err := p.db.Table("vulnerabilities").
		Select("id, cvss_score, has_exploit, in_kev, affected_hosts, fixed_version").
		Where("id IN ?", vulnIDs).
		Scan(&rows).Error; err != nil {
		return err
	}

	// 批量查询是否有公网暴露主机
	internetFacingMap := p.queryInternetFacing(vulnIDs)

	for _, row := range rows {
		// 1. CVSS 归一化（0~1）
		cvssNorm := row.CvssScore / 10.0

		// 2. 利用状态评分
		var exploitScore float64
		if row.InKEV {
			exploitScore = 1.0
		} else if row.HasExploit {
			exploitScore = 0.7
		}

		// 3. 暴露面评分
		hostRatio := float64(row.AffectedHosts) / float64(totalHosts)
		if hostRatio > 1.0 {
			hostRatio = 1.0
		}
		internetFacing := 0.0
		if internetFacingMap[row.ID] {
			internetFacing = 1.0
		}
		exposureScore := hostRatio*0.5 + internetFacing*0.5

		// 4. 补丁可用性评分（有补丁 = 可行动 = 优先级更高）
		patchScore := 0.2
		if row.FixedVersion != "" {
			patchScore = 0.8
		}

		// 综合优先级分
		priorityScore := p.WeightCVSS*cvssNorm +
			p.WeightExploit*exploitScore +
			p.WeightExposure*exposureScore +
			p.WeightPatch*patchScore

		// 更新数据库
		p.db.Table("vulnerabilities").Where("id = ?", row.ID).
			Updates(map[string]any{
				"priority_score": priorityScore,
				"exposure_score": exposureScore,
			})
	}

	return nil
}

// RecalculateOne 计算单个漏洞的优先级评分
func (p *PriorityCalculator) RecalculateOne(vulnID uint) (float64, error) {
	var totalHosts int64
	if err := p.db.Table("hosts").Where("status = ?", "online").Count(&totalHosts).Error; err != nil {
		return 0, fmt.Errorf("查询主机总数失败: %w", err)
	}
	if totalHosts == 0 {
		totalHosts = 1
	}

	if err := p.recalculateBatch([]uint{vulnID}, totalHosts); err != nil {
		return 0, err
	}

	var score float64
	p.db.Table("vulnerabilities").Select("priority_score").Where("id = ?", vulnID).Scan(&score)
	return score, nil
}

// queryInternetFacing 查询漏洞关联的主机是否有公网暴露
func (p *PriorityCalculator) queryInternetFacing(vulnIDs []uint) map[uint]bool {
	result := make(map[uint]bool)

	// 查询受影响主机中是否有对外端口的
	type row struct {
		VulnID uint `gorm:"column:vuln_id"`
	}
	var rows []row

	p.db.Raw(`
		SELECT DISTINCT hv.vuln_id
		FROM host_vulnerabilities hv
		JOIN ports p ON p.host_id = hv.host_id
		WHERE hv.vuln_id IN ?
		  AND hv.status = 'unpatched'
		  AND p.listen_address NOT IN ('127.0.0.1', '::1', '0.0.0.0', '::')
	`, vulnIDs).Scan(&rows)

	for _, r := range rows {
		result[r.VulnID] = true
	}
	return result
}

// ============================================================
// CVSS 向量分析与漏洞类型推断
// ============================================================

// parseCVSSMetrics 从 CVSS v3 向量字符串解析各指标
func parseCVSSMetrics(vector string) map[string]string {
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}
	return metrics
}

// classifyFromCVSSVector 根据 CVSS 向量和 CWE 推断攻击向量和漏洞类型
func classifyFromCVSSVector(cvssVector, cweID string) (attackVector, vulnType string) {
	if cvssVector == "" {
		return model.AttackVectorNetwork, model.VulnTypeUnknown
	}

	metrics := parseCVSSMetrics(cvssVector)

	// 攻击向量
	switch metrics["AV"] {
	case "N":
		attackVector = model.AttackVectorNetwork
	case "A":
		attackVector = model.AttackVectorAdjacent
	case "L":
		attackVector = model.AttackVectorLocal
	case "P":
		attackVector = model.AttackVectorPhysical
	default:
		attackVector = model.AttackVectorNetwork
	}

	// 优先通过 CWE 推断漏洞类型
	if cweID != "" {
		vulnType = classifyByCWE(cweID)
		if vulnType != model.VulnTypeOther {
			return
		}
	}

	// 回退：通过 CVSS 向量启发式推断
	vulnType = classifyByCVSSMetrics(metrics)
	return
}

// classifyByCWE 根据 CWE 编号推断漏洞类型
func classifyByCWE(cweID string) string {
	// CWE → 漏洞类型映射（覆盖主流 CWE）
	rce := map[string]bool{
		"CWE-78": true, "CWE-94": true, "CWE-95": true, "CWE-96": true,
		"CWE-97": true, "CWE-98": true, "CWE-502": true, "CWE-917": true,
		"CWE-1321": true,
	}
	lpe := map[string]bool{
		"CWE-269": true, "CWE-264": true, "CWE-250": true, "CWE-266": true,
		"CWE-268": true, "CWE-732": true,
	}
	dos := map[string]bool{
		"CWE-400": true, "CWE-770": true, "CWE-674": true, "CWE-835": true,
		"CWE-787": true, "CWE-120": true, "CWE-121": true, "CWE-122": true,
	}
	infoDisclosure := map[string]bool{
		"CWE-200": true, "CWE-209": true, "CWE-532": true, "CWE-538": true,
		"CWE-497": true, "CWE-611": true,
	}
	authBypass := map[string]bool{
		"CWE-287": true, "CWE-288": true, "CWE-290": true, "CWE-294": true,
		"CWE-306": true, "CWE-862": true, "CWE-863": true,
	}
	sqli := map[string]bool{"CWE-89": true, "CWE-564": true}
	xss := map[string]bool{"CWE-79": true, "CWE-80": true}
	ssrf := map[string]bool{"CWE-918": true}

	switch {
	case rce[cweID]:
		return model.VulnTypeRCE
	case lpe[cweID]:
		return model.VulnTypeLPE
	case sqli[cweID]:
		return model.VulnTypeSQLi
	case xss[cweID]:
		return model.VulnTypeXSS
	case ssrf[cweID]:
		return model.VulnTypeSSRF
	case authBypass[cweID]:
		return model.VulnTypeAuthBypass
	case infoDisclosure[cweID]:
		return model.VulnTypeInfoDisclosure
	case dos[cweID]:
		return model.VulnTypeDoS
	default:
		return model.VulnTypeOther
	}
}

// classifyByCVSSMetrics 根据 CVSS 向量指标启发式推断漏洞类型
func classifyByCVSSMetrics(metrics map[string]string) string {
	av := metrics["AV"]
	pr := metrics["PR"]
	s := metrics["S"]
	c := metrics["C"]
	i := metrics["I"]
	a := metrics["A"]

	switch {
	// RCE：远程 + 高完整性/机密性影响 + 低权限要求
	case av == "N" && (c == "H" || i == "H") && (pr == "N" || pr == "L"):
		return model.VulnTypeRCE

	// LPE：本地 + Scope Changed（权限提升跨安全域）
	case av == "L" && s == "C":
		return model.VulnTypeLPE

	// Info Disclosure：仅机密性受影响
	case c == "H" && i == "N" && a == "N":
		return model.VulnTypeInfoDisclosure

	// DoS：仅可用性受影响
	case c == "N" && i == "N" && a == "H":
		return model.VulnTypeDoS

	// Auth Bypass：远程 + 无需认证 + 完整性影响
	case av == "N" && pr == "N" && i == "H":
		return model.VulnTypeAuthBypass

	default:
		return model.VulnTypeOther
	}
}

// ============================================================
// P0 ~ P3 通报分级
// ============================================================

// ClassifyBulletinPriority 根据漏洞属性计算通报分级（P0 ~ P3）
func ClassifyBulletinPriority(vuln *model.Vulnerability) (string, model.PriorityFactors) {
	factors := model.PriorityFactors{
		CvssScore:    vuln.CvssScore,
		CvssVector:   vuln.CvssVector,
		AttackVector: vuln.AttackVector,
		VulnType:     vuln.VulnType,
		HasExploit:   vuln.HasExploit,
		InKEV:        vuln.InKEV,
		PatchAvail:   vuln.PatchAvailable,
		EpssScore:    vuln.EpssScore,
	}

	isRemote := vuln.AttackVector == model.AttackVectorNetwork || vuln.AttackVector == ""
	isRCE := vuln.VulnType == model.VulnTypeRCE
	isLPE := vuln.VulnType == model.VulnTypeLPE

	// P0：紧急
	// - 在野利用 + 远程 + CVSS ≥ 9.0
	// - 有 EXP + RCE + CVSS ≥ 9.0
	// - 0day（无补丁）+ 在野利用
	if vuln.InKEV && isRemote && vuln.CvssScore >= 9.0 {
		factors.Reason = "在野利用 (KEV) + 远程可达 + CVSS ≥ 9.0"
		return model.BulletinPriorityP0, factors
	}
	if vuln.HasExploit && isRCE && vuln.CvssScore >= 9.0 {
		factors.Reason = "有公开 EXP + 远程代码执行 + CVSS ≥ 9.0"
		return model.BulletinPriorityP0, factors
	}
	if vuln.InKEV && !vuln.PatchAvailable {
		factors.Reason = "在野利用 (KEV) + 无可用补丁 (0day)"
		return model.BulletinPriorityP0, factors
	}

	// P1：高
	// - 有 EXP + CVSS ≥ 7.0 + 远程
	// - RCE 无 EXP 但 CVSS ≥ 9.0
	// - LPE + 有 EXP
	// - 在 KEV 但 CVSS < 9.0
	if vuln.HasExploit && vuln.CvssScore >= 7.0 && isRemote {
		factors.Reason = "有公开 EXP + CVSS ≥ 7.0 + 远程可达"
		return model.BulletinPriorityP1, factors
	}
	if isRCE && vuln.CvssScore >= 9.0 {
		factors.Reason = "远程代码执行 + CVSS ≥ 9.0"
		return model.BulletinPriorityP1, factors
	}
	if isLPE && vuln.HasExploit {
		factors.Reason = "本地提权 + 有公开 EXP"
		return model.BulletinPriorityP1, factors
	}
	if vuln.InKEV {
		factors.Reason = "在 CISA KEV 目录"
		return model.BulletinPriorityP1, factors
	}
	// Critical + CVSS ≥ 9.0 兜底（覆盖 vulnType 缺失的高危漏洞）
	if vuln.Severity == "critical" && vuln.CvssScore >= 9.0 {
		factors.Reason = "Critical 漏洞 + CVSS ≥ 9.0"
		return model.BulletinPriorityP1, factors
	}

	// P2：中
	// - CVSS ≥ 7.0 无 EXP
	// - 有 EXP 但仅本地 + CVSS ≥ 4.0
	// - Auth Bypass / SSRF
	if vuln.CvssScore >= 7.0 {
		factors.Reason = "CVSS ≥ 7.0"
		return model.BulletinPriorityP2, factors
	}
	if vuln.HasExploit && vuln.CvssScore >= 4.0 {
		factors.Reason = "有公开 EXP + CVSS ≥ 4.0"
		return model.BulletinPriorityP2, factors
	}
	if vuln.VulnType == model.VulnTypeAuthBypass || vuln.VulnType == model.VulnTypeSSRF {
		factors.Reason = "认证绕过 / SSRF 类型漏洞"
		return model.BulletinPriorityP2, factors
	}

	// P3：低
	factors.Reason = "中低危漏洞"
	return model.BulletinPriorityP3, factors
}
