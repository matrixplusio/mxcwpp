// Package api 提供 HTTP API 处理器
package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// AlertWhitelistHandler 告警白名单 API 处理器
type AlertWhitelistHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewAlertWhitelistHandler 创建告警白名单 API 处理器
func NewAlertWhitelistHandler(db *gorm.DB, logger *zap.Logger) *AlertWhitelistHandler {
	return &AlertWhitelistHandler{db: db, logger: logger}
}

// ListWhitelistRequest 查询白名单列表请求
type ListWhitelistRequest struct {
	Page     int    `form:"page" binding:"omitempty,min=1"`
	PageSize int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	Keyword  string `form:"keyword"`
	// Status 按生效状态筛选：active（生效中）/ expired（已过期）/ disabled（已停用）。
	Status string `form:"status"`
	// ExpiringDays 只看 N 天内到期、仍生效的条目，用于到期前复查。
	ExpiringDays int `form:"expiring_days" binding:"omitempty,min=1,max=365"`
}

// alertWhitelistItem 列表项：条目本身加上它压下了多少命中。
//
// 抑制规则不是一次性的决定，它会持续生效、持续压下命中。看不到它压下了什么，
// 就无从判断它还该不该留着。
type alertWhitelistItem struct {
	model.AlertWhitelist
	SuppressedHits   int64            `json:"suppressed_hits"`
	LastSuppressedAt *model.LocalTime `json:"last_suppressed_at,omitempty"`
}

// ListWhitelist 获取白名单列表
// GET /api/v1/alerts/whitelist
func (h *AlertWhitelistHandler) ListWhitelist(c *gin.Context) {
	var req ListWhitelistRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}

	now := time.Now()
	query := h.db.Model(&model.AlertWhitelist{})
	if req.Keyword != "" {
		query = query.Where("name LIKE ? OR reason LIKE ?", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}
	switch req.Status {
	case "active":
		query = query.Where("enabled = ? AND (expires_at IS NULL OR expires_at > ?)", true, now)
	case "expired":
		query = query.Where("expires_at IS NOT NULL AND expires_at <= ?", now)
	case "disabled":
		query = query.Where("enabled = ?", false)
	}
	if req.ExpiringDays > 0 {
		query = query.Where("enabled = ? AND expires_at > ? AND expires_at <= ?",
			true, now, now.AddDate(0, 0, req.ExpiringDays))
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询白名单总数失败", zap.Error(err))
		InternalError(c, "查询白名单失败")
		return
	}

	var rows []model.AlertWhitelist
	offset := (req.Page - 1) * req.PageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(req.PageSize).Find(&rows).Error; err != nil {
		h.logger.Error("查询白名单列表失败", zap.Error(err))
		InternalError(c, "查询白名单失败")
		return
	}

	items := make([]alertWhitelistItem, len(rows))
	ids := make([]uint, len(rows))
	for i := range rows {
		items[i].AlertWhitelist = rows[i]
		ids[i] = rows[i].ID
	}
	if len(ids) > 0 {
		var stats []struct {
			SuppressionID uint
			Hits          int64
			Last          *model.LocalTime
		}
		h.db.Model(&model.Alert{}).
			Select("suppression_id, SUM(hit_count) AS hits, MAX(last_seen_at) AS last").
			Where("suppression_id IN ?", ids).Group("suppression_id").Scan(&stats)
		byID := make(map[uint]int, len(rows))
		for i := range rows {
			byID[rows[i].ID] = i
		}
		for _, st := range stats {
			if i, ok := byID[st.SuppressionID]; ok {
				items[i].SuppressedHits = st.Hits
				items[i].LastSuppressedAt = st.Last
			}
		}
	}

	Success(c, gin.H{
		"items":      items,
		"total":      total,
		"page":       req.Page,
		"page_size":  req.PageSize,
		"total_page": (int(total) + req.PageSize - 1) / req.PageSize,
	})
}

// CreateWhitelistRequest 创建白名单请求
type CreateWhitelistRequest struct {
	Name         string `json:"name" binding:"required"`
	RuleID       string `json:"rule_id"`
	HostID       string `json:"host_id"`
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	Exe          string `json:"exe"`            // 进程 basename，按 exe/comm 匹配
	Cmdline      string `json:"cmdline"`        // 命令行子串，大小写不敏感包含匹配
	SourceIPCIDR string `json:"source_ip_cidr"` // 源 IP CIDR（供 ScanDetector 等使用）
	Reason       string `json:"reason"`
	// ExpiresInDays 有效期天数，默认 30，最长 90。
	ExpiresInDays int `json:"expires_in_days"`
}

const (
	// 豁免期限短一些：判断依据会过时（进程换了、业务变了），到期前要复核一次才续。
	suppressionDefaultDays = 30
	suppressionMaxDays     = 90
)

// suppressionExpiry 由请求的天数算出到期时间；0 取默认值，越界返回错误信息。
func suppressionExpiry(days int) (*model.LocalTime, string) {
	if days == 0 {
		days = suppressionDefaultDays
	}
	if days < 1 || days > suppressionMaxDays {
		return nil, fmt.Sprintf("有效期需在 1 到 %d 天之间", suppressionMaxDays)
	}
	at := model.ToLocalTime(time.Now().AddDate(0, 0, days))
	return &at, ""
}

// validateSuppression 校验一条抑制规则能否保存，返回不通过的原因。
//
// 除「至少有一个收窄维度」外，还要求：
//   - 写明原因：抑制规则会长期压下命中，事后要能回答当初为什么这么做；
//   - 可能覆盖 critical 告警的条目必须约束具体证据（进程 / 命令行 / 来源网段）。
//     只写「规则 + 主机」等于让这台主机上的 critical 规则整体失明。
func (h *AlertWhitelistHandler) validateSuppression(w *model.AlertWhitelist) string {
	if !validateNarrowing(w.HostID, w.Exe, w.Cmdline, w.SourceIPCIDR) {
		return "白名单必须至少指定 host_id / exe / cmdline / source_ip_cidr 之一，否则不会生效"
	}
	if msg := w.ScopeProblem(); msg != "" {
		return msg
	}
	if expr := h.ruleExpression(w.RuleID); expr != "" && w.ConflictsWithRule(expr) {
		return "该豁免的进程正是这条规则要检测的进程，会让规则整体失效；请改为约束命令行或限定主机"
	}
	if strings.TrimSpace(w.Reason) == "" {
		return "请填写抑制原因"
	}
	if h.mayCoverCritical(w.RuleID, w.Severity) && !w.HasEvidenceCondition() {
		return "该条目可能压下 critical 告警，必须指定进程、命令行或来源网段之一，不能只按规则与主机豁免"
	}
	return ""
}

// ruleExpression 取 CEL 规则的表达式，供冲突检查用；不是 CEL 规则或查不到时返回空。
func (h *AlertWhitelistHandler) ruleExpression(ruleID string) string {
	id, ok := strings.CutPrefix(strings.TrimSpace(ruleID), "cel-")
	if !ok {
		return ""
	}
	var expr string
	h.db.Model(&model.DetectionRule{}).Select("expression").Where("id = ?", id).Scan(&expr)
	return expr
}

// mayCoverCritical 判断条目是否可能压下 critical 告警。拿不准时按「可能」处理。
func (h *AlertWhitelistHandler) mayCoverCritical(ruleID, severity string) bool {
	if severity != "" && severity != "*" {
		return severity == "critical"
	}
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" || ruleID == "*" || strings.HasPrefix(ruleID, "ioc-") {
		return true
	}
	var sev string
	switch {
	case strings.HasPrefix(ruleID, "cel-"):
		h.db.Model(&model.DetectionRule{}).Select("severity").Where("id = ?", strings.TrimPrefix(ruleID, "cel-")).Scan(&sev)
	case strings.HasPrefix(ruleID, "seq-"):
		h.db.Model(&model.SequenceRule{}).Select("severity").Where("id = ?", strings.TrimPrefix(ruleID, "seq-")).Scan(&sev)
	}
	return sev == "" || sev == "critical"
}

// operatorOf 当前登录用户；取不到时标记为 unknown 而不是冒用某个账号。
func operatorOf(c *gin.Context) string {
	if u := c.GetString("username"); u != "" {
		return u
	}
	return "unknown"
}

// validateNarrowing 校验条目是否具备可生效的收窄维度。
//
// 两条生效路径的要求不同，任一满足即可：
//   - CEL/EDR 告警路径（AlertWhitelist.MatchesAlert）要求 host/exe/cmdline 至少一个具体值；
//   - ScanDetector 路径只读 source_ip_cidr。
//
// 都不满足的条目写进去也不会命中任何一条路径，属于静默失效，在接口层直接拒绝。
func validateNarrowing(hostID, exe, cmdline, sourceIPCIDR string) bool {
	if sourceIPCIDR != "" {
		return true
	}
	w := model.AlertWhitelist{HostID: hostID, Exe: exe, Cmdline: cmdline}
	return w.HasConcreteNarrowing()
}

// CreateWhitelist 创建白名单条目
// POST /api/v1/alerts/whitelist
func (h *AlertWhitelistHandler) CreateWhitelist(c *gin.Context) {
	var req CreateWhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	expires, msg := suppressionExpiry(req.ExpiresInDays)
	if msg != "" {
		BadRequest(c, msg)
		return
	}
	item := &model.AlertWhitelist{
		Name:         req.Name,
		RuleID:       req.RuleID,
		HostID:       req.HostID,
		Category:     req.Category,
		Severity:     req.Severity,
		Exe:          req.Exe,
		Cmdline:      req.Cmdline,
		SourceIPCIDR: req.SourceIPCIDR,
		Reason:       req.Reason,
		CreatedBy:    operatorOf(c),
		ExpiresAt:    expires,
		Enabled:      true,
	}
	if msg := h.validateSuppression(item); msg != "" {
		BadRequest(c, msg)
		return
	}

	if err := h.db.Create(item).Error; err != nil {
		h.logger.Error("创建白名单失败", zap.Error(err))
		InternalError(c, "创建白名单失败")
		return
	}

	h.logger.Info("白名单已创建", zap.Uint("id", item.ID), zap.String("name", item.Name))
	Success(c, item)
}

// UpdateWhitelistRequest 更新白名单请求
type UpdateWhitelistRequest struct {
	Name         string `json:"name" binding:"required"`
	RuleID       string `json:"rule_id"`
	HostID       string `json:"host_id"`
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	Exe          string `json:"exe"`
	Cmdline      string `json:"cmdline"`
	SourceIPCIDR string `json:"source_ip_cidr"`
	Reason       string `json:"reason"`
	// ExpiresInDays 大于 0 时从现在起续期这么多天；为 0 保留原到期时间。
	ExpiresInDays int `json:"expires_in_days"`
	// Enabled 为空保持不变；false 停用（保留记录与它压下过的命中）。
	Enabled *bool `json:"enabled"`
}

// UpdateWhitelist 更新白名单条目
// PUT /api/v1/alerts/whitelist/:id
func (h *AlertWhitelistHandler) UpdateWhitelist(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的白名单ID")
		return
	}

	var item model.AlertWhitelist
	if err := h.db.First(&item, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "白名单条目不存在")
			return
		}
		InternalError(c, "查询白名单失败")
		return
	}

	var req UpdateWhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	item.Name = req.Name
	item.RuleID = req.RuleID
	item.HostID = req.HostID
	item.Category = req.Category
	item.Severity = req.Severity
	item.Exe = req.Exe
	item.Cmdline = req.Cmdline
	item.SourceIPCIDR = req.SourceIPCIDR
	item.Reason = req.Reason
	if req.ExpiresInDays != 0 {
		expires, msg := suppressionExpiry(req.ExpiresInDays)
		if msg != "" {
			BadRequest(c, msg)
			return
		}
		item.ExpiresAt = expires
	}
	if req.Enabled != nil {
		item.Enabled = *req.Enabled
	}
	// 停用的条目不压下任何命中，总允许保存：历史上不合规的条目也要能先停掉再修。
	if item.Enabled {
		if msg := h.validateSuppression(&item); msg != "" {
			BadRequest(c, msg)
			return
		}
	}

	// Select("*") 让 false 的 enabled 也写进去：GORM 默认跳过零值。
	if err := h.db.Select("*").Save(&item).Error; err != nil {
		h.logger.Error("更新白名单失败", zap.Error(err))
		InternalError(c, "更新白名单失败")
		return
	}

	Success(c, item)
}

// DeleteWhitelist 删除白名单条目
// DELETE /api/v1/alerts/whitelist/:id
func (h *AlertWhitelistHandler) DeleteWhitelist(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的白名单ID")
		return
	}

	result := h.db.Delete(&model.AlertWhitelist{}, id)
	if result.Error != nil {
		h.logger.Error("删除白名单失败", zap.Error(result.Error))
		InternalError(c, "删除白名单失败")
		return
	}
	if result.RowsAffected == 0 {
		NotFound(c, "白名单条目不存在")
		return
	}

	h.logger.Info("白名单已删除", zap.Uint64("id", id))
	SuccessWithMessage(c, "删除成功", nil)
}
