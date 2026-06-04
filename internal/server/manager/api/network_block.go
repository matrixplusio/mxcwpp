// Package api 提供 HTTP API 处理器
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/manager/sd"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// NetworkBlockHandler 网络阻断 API 处理器
type NetworkBlockHandler struct {
	db           *gorm.DB
	logger       *zap.Logger
	acDispatcher *sd.ACDispatcher
}

// NewNetworkBlockHandler 创建网络阻断处理器
func NewNetworkBlockHandler(db *gorm.DB, logger *zap.Logger, acDispatcher *sd.ACDispatcher) *NetworkBlockHandler {
	return &NetworkBlockHandler{db: db, logger: logger, acDispatcher: acDispatcher}
}

// ListRules 查询阻断规则列表
// GET /api/v1/network-block/rules?host_id=xxx&status=active&page=1&page_size=20
func (h *NetworkBlockHandler) ListRules(c *gin.Context) {
	hostID := c.Query("host_id")
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	q := h.db.Model(&model.NetworkBlockRule{})
	if hostID != "" {
		q = q.Where("host_id = ?", hostID)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}

	var total int64
	q.Count(&total)

	var rules []model.NetworkBlockRule
	if err := q.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&rules).Error; err != nil {
		h.logger.Error("查询阻断规则失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, PaginatedData{Total: total, Items: rules})
}

type createBlockRuleReq struct {
	HostID    string `json:"host_id" binding:"required"`
	IP        string `json:"ip" binding:"required"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
	Reason    string `json:"reason"`
}

// CreateRule 创建阻断规则
// POST /api/v1/network-block/rules
func (h *NetworkBlockHandler) CreateRule(c *gin.Context) {
	var req createBlockRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "参数错误")
		return
	}

	// 验证 IP 格式
	if net.ParseIP(req.IP) == nil {
		// 尝试 CIDR
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			BadRequest(c, "IP 地址格式无效")
			return
		}
	}

	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.Direction == "" {
		req.Direction = "outbound"
	}

	username, _ := c.Get("username")

	rule := model.NetworkBlockRule{
		HostID:    req.HostID,
		IP:        req.IP,
		Port:      req.Port,
		Protocol:  req.Protocol,
		Direction: req.Direction,
		Reason:    req.Reason,
		Source:    "manual",
		Status:    "pending",
		CreatedBy: fmt.Sprintf("%v", username),
	}

	if err := h.db.Create(&rule).Error; err != nil {
		h.logger.Error("创建阻断规则失败", zap.Error(err))
		InternalError(c, "创建失败")
		return
	}

	// 下发阻断命令到 AC
	if err := h.dispatchBlockCommand(rule); err != nil {
		h.logger.Error("下发阻断命令失败", zap.Error(err))
		h.db.Model(&rule).Update("status", "failed")
	} else {
		h.db.Model(&rule).Update("status", "active")
	}

	Success(c, rule)
}

// RemoveRule 移除阻断规则（解除阻断）
// POST /api/v1/network-block/rules/:id/remove
func (h *NetworkBlockHandler) RemoveRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的 ID")
		return
	}

	var rule model.NetworkBlockRule
	if err := h.db.First(&rule, id).Error; err != nil {
		NotFound(c, "规则不存在")
		return
	}

	rule.Status = "removed"
	h.db.Save(&rule)

	// 下发解除阻断命令
	_ = h.dispatchUnblockCommand(rule)

	Success(c, rule)
}

// DeleteRule 删除阻断规则记录
// DELETE /api/v1/network-block/rules/:id
func (h *NetworkBlockHandler) DeleteRule(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的 ID")
		return
	}

	if err := h.db.Delete(&model.NetworkBlockRule{}, id).Error; err != nil {
		InternalError(c, "删除失败")
		return
	}

	SuccessMessage(c, "已删除")
}

// dispatchBlockCommand 下发阻断命令（通过 AC 精准路由/广播）
func (h *NetworkBlockHandler) dispatchBlockCommand(rule model.NetworkBlockRule) error {
	if h.acDispatcher == nil {
		h.logger.Warn("阻断命令未下发: AC dispatcher 未初始化")
		return nil
	}

	taskData := map[string]any{
		"action":    "block_ip",
		"ip":        rule.IP,
		"port":      rule.Port,
		"protocol":  rule.Protocol,
		"direction": rule.Direction,
		"rule_id":   rule.ID,
	}
	taskJSON, _ := json.Marshal(taskData)

	h.logger.Info("下发网络阻断命令",
		zap.String("host_id", rule.HostID),
		zap.String("ip", rule.IP),
		zap.Int("port", rule.Port))

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			DataType:   9997,
			ObjectName: "edr",
			Data:       string(taskJSON),
		}},
	}

	return h.acDispatcher.SendCommand(rule.HostID, cmd)
}

// dispatchUnblockCommand 下发解除阻断命令
func (h *NetworkBlockHandler) dispatchUnblockCommand(rule model.NetworkBlockRule) error {
	if h.acDispatcher == nil {
		return nil
	}

	taskData := map[string]any{
		"action":    "unblock_ip",
		"ip":        rule.IP,
		"port":      rule.Port,
		"protocol":  rule.Protocol,
		"direction": rule.Direction,
		"rule_id":   rule.ID,
	}
	taskJSON, _ := json.Marshal(taskData)

	h.logger.Info("下发解除阻断命令",
		zap.String("host_id", rule.HostID),
		zap.String("ip", rule.IP))

	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			DataType:   9997,
			ObjectName: "edr",
			Data:       string(taskJSON),
		}},
	}

	return h.acDispatcher.SendCommand(rule.HostID, cmd)
}
