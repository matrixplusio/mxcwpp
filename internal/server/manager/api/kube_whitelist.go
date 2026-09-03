package api

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 告警类型显示名称
var alarmTypeTextMap = map[string]string{
	"container_escape":     "容器逃逸",
	"abnormal_process":     "异常进程",
	"abnormal_network":     "异常网络",
	"file_tamper":          "文件篡改",
	"privilege_escalation": "提权行为",
	"reverse_shell":        "反弹Shell",
	"crypto_mining":        "挖矿行为",
}

// KubeWhitelistHandler 容器告警白名单 API Handler
type KubeWhitelistHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewKubeWhitelistHandler 创建白名单 Handler
func NewKubeWhitelistHandler(db *gorm.DB, logger *zap.Logger) *KubeWhitelistHandler {
	return &KubeWhitelistHandler{db: db, logger: logger}
}

// whitelistItem 白名单列表项（包含 alarmTypesText 计算字段）
type whitelistItem struct {
	model.KubeWhitelist
	AlarmTypesText string `json:"alarmTypesText"`
}

// ListWhitelist 白名单列表
func (h *KubeWhitelistHandler) ListWhitelist(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	search := c.Query("search")
	clusterID := c.Query("cluster_id")

	query := h.db.Model(&model.KubeWhitelist{})

	if search != "" {
		query = query.Where("name LIKE ?", "%"+search+"%")
	}
	if clusterID != "" {
		query = query.Where("cluster_id = ?", clusterID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询白名单总数失败", zap.Error(err))
		InternalError(c, "查询白名单列表失败")
		return
	}

	var rules []model.KubeWhitelist
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&rules).Error; err != nil {
		h.logger.Error("查询白名单列表失败", zap.Error(err))
		InternalError(c, "查询白名单列表失败")
		return
	}

	// 添加 alarmTypesText
	items := make([]whitelistItem, 0, len(rules))
	for _, r := range rules {
		var texts []string
		for _, t := range r.AlarmTypes {
			if text, ok := alarmTypeTextMap[t]; ok {
				texts = append(texts, text)
			} else {
				texts = append(texts, t)
			}
		}
		items = append(items, whitelistItem{
			KubeWhitelist:  r,
			AlarmTypesText: strings.Join(texts, "、"),
		})
	}

	SuccessPaginated(c, total, items)
}

// CreateWhitelist 创建白名单
func (h *KubeWhitelistHandler) CreateWhitelist(c *gin.Context) {
	var req struct {
		Name       string   `json:"name" binding:"required"`
		ClusterID  *uint    `json:"clusterId"`
		AlarmTypes []string `json:"alarmTypes"`
		Namespace  string   `json:"namespace"`
		PodPattern string   `json:"podPattern"`
		Remark     string   `json:"remark"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	rule := model.KubeWhitelist{
		Name:       req.Name,
		ClusterID:  req.ClusterID,
		AlarmTypes: model.StringArray(req.AlarmTypes),
		Namespace:  req.Namespace,
		PodPattern: req.PodPattern,
		Status:     model.KubeWhitelistStatusEnabled,
		Remark:     req.Remark,
	}

	// 关联集群名称
	if req.ClusterID != nil {
		var cluster model.KubeCluster
		if err := h.db.First(&cluster, *req.ClusterID).Error; err == nil {
			rule.ClusterName = cluster.Name
		}
	}

	if err := h.db.Create(&rule).Error; err != nil {
		h.logger.Error("创建白名单失败", zap.Error(err))
		InternalError(c, "创建白名单失败")
		return
	}

	SuccessWithMessage(c, "已创建", rule)
}

// UpdateWhitelist 更新白名单
func (h *KubeWhitelistHandler) UpdateWhitelist(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的白名单 ID")
		return
	}

	var rule model.KubeWhitelist
	if err := h.db.First(&rule, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "白名单不存在")
			return
		}
		h.logger.Error("查询白名单失败", zap.Error(err))
		InternalError(c, "查询白名单失败")
		return
	}

	var req struct {
		Name       *string  `json:"name"`
		ClusterID  *uint    `json:"clusterId"`
		AlarmTypes []string `json:"alarmTypes"`
		Namespace  *string  `json:"namespace"`
		PodPattern *string  `json:"podPattern"`
		Status     *string  `json:"status"`
		Remark     *string  `json:"remark"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	if req.Name != nil {
		rule.Name = *req.Name
	}
	if req.ClusterID != nil {
		rule.ClusterID = req.ClusterID
		var cluster model.KubeCluster
		if err := h.db.First(&cluster, *req.ClusterID).Error; err == nil {
			rule.ClusterName = cluster.Name
		}
	}
	if req.AlarmTypes != nil {
		rule.AlarmTypes = model.StringArray(req.AlarmTypes)
	}
	if req.Namespace != nil {
		rule.Namespace = *req.Namespace
	}
	if req.PodPattern != nil {
		rule.PodPattern = *req.PodPattern
	}
	if req.Status != nil {
		rule.Status = model.KubeWhitelistStatus(*req.Status)
	}
	if req.Remark != nil {
		rule.Remark = *req.Remark
	}

	if err := h.db.Save(&rule).Error; err != nil {
		h.logger.Error("更新白名单失败", zap.Error(err))
		InternalError(c, "更新白名单失败")
		return
	}

	SuccessWithMessage(c, "已更新", rule)
}

// DeleteWhitelist 删除白名单
func (h *KubeWhitelistHandler) DeleteWhitelist(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		BadRequest(c, "无效的白名单 ID")
		return
	}

	var rule model.KubeWhitelist
	if err := h.db.First(&rule, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "白名单不存在")
			return
		}
		h.logger.Error("查询白名单失败", zap.Error(err))
		InternalError(c, "查询白名单失败")
		return
	}

	if err := h.db.Delete(&rule).Error; err != nil {
		h.logger.Error("删除白名单失败", zap.Error(err))
		InternalError(c, "删除白名单失败")
		return
	}

	SuccessMessage(c, "已删除")
}
