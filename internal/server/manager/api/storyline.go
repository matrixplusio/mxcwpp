package api

import (
	"context"
	"strconv"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// StorylineHandler 攻击故事线 API 处理器
//
// storyline_events 数据可能在 MySQL 或 ClickHouse，按 feature_flag.data_source.
// storyline_events 决定读路径。chConn 为 nil 时强制走 MySQL。
type StorylineHandler struct {
	db     *gorm.DB
	chConn chdriver.Conn // 可为 nil
	logger *zap.Logger
}

// NewStorylineHandler 创建攻击故事线 API 处理器
func NewStorylineHandler(db *gorm.DB, logger *zap.Logger) *StorylineHandler {
	return &StorylineHandler{db: db, logger: logger}
}

// SetClickHouse 启动时注入 CH 连接。
func (h *StorylineHandler) SetClickHouse(conn chdriver.Conn) {
	h.chConn = conn
}

// readEventsSource 查 feature_flag 当前 storyline_events 数据源。
// DB 查询失败回落 "mysql"。每次请求查 DB 简单可靠，QPS 低（详情页才用）。
func (h *StorylineHandler) readEventsSource() string {
	var f model.FeatureFlag
	if err := h.db.Where("flag_key = ?", model.FlagDataSourceStorylineEvents).First(&f).Error; err != nil {
		return "mysql"
	}
	if f.Value != "ch" || h.chConn == nil {
		return "mysql"
	}
	return "ch"
}

// ListStorylines 查看攻击故事线列表
func (h *StorylineHandler) ListStorylines(c *gin.Context) {
	hostID := c.Query("host_id")
	severity := c.Query("severity")
	status := c.Query("status")

	query := h.db.Model(&model.Storyline{})
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	query = query.Order("last_seen_at DESC")

	var total int64
	if err := query.Count(&total).Error; err != nil {
		InternalError(c, "查询故事线失败")
		return
	}

	page, pageSize := ParsePagination(c)
	var stories []model.Storyline
	if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&stories).Error; err != nil {
		InternalError(c, "查询故事线失败")
		return
	}

	SuccessPaginated(c, total, stories)
}

// GetStoryline 获取故事线详情（含事件时间线，分页）
//
// 单 storyline 的 events 可达数万级（EDR ebpf 全量关联），全量返回 JSON
// 体积过大导致浏览器解析+渲染卡死。改用分页：默认 page=1 page_size=100，
// 上限 500；UI 增量加载。
func (h *StorylineHandler) GetStoryline(c *gin.Context) {
	storyID := c.Param("story_id")

	var story model.Storyline
	if err := h.db.Where("story_id = ?", storyID).First(&story).Error; err != nil {
		NotFound(c, "故事线不存在")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "100"))
	if pageSize < 1 {
		pageSize = 100
	}
	if pageSize > 500 {
		pageSize = 500
	}

	var eventsTotal int64
	var events []model.StorylineEvent

	source := h.readEventsSource()
	switch source {
	case "ch":
		var err error
		eventsTotal, events, err = h.queryEventsCH(storyID, page, pageSize)
		if err != nil {
			h.logger.Warn("CH 读取 storyline_events 失败，回落 MySQL",
				zap.String("story_id", storyID), zap.Error(err))
			h.db.Model(&model.StorylineEvent{}).Where("story_id = ?", storyID).Count(&eventsTotal)
			h.db.Where("story_id = ?", storyID).
				Order("timestamp ASC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&events)
		}
	default:
		h.db.Model(&model.StorylineEvent{}).Where("story_id = ?", storyID).Count(&eventsTotal)
		h.db.Where("story_id = ?", storyID).
			Order("timestamp ASC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&events)
	}

	Success(c, gin.H{
		"storyline":        story,
		"events":           events,
		"events_total":     eventsTotal,
		"events_page":      page,
		"events_page_size": pageSize,
		"_source":          source,
	})
}

// queryEventsCH 从 ClickHouse 查 story 的事件总数 + 当前页数据。
func (h *StorylineHandler) queryEventsCH(storyID string, page, pageSize int) (int64, []model.StorylineEvent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var total uint64
	if err := h.chConn.QueryRow(ctx,
		"SELECT count() FROM storyline_events WHERE story_id = ?", storyID).Scan(&total); err != nil {
		return 0, nil, err
	}

	rows, err := h.chConn.Query(ctx, `
		SELECT id, story_id, host_id, data_type, event_type, pid, exe, detail, rule_name, severity, timestamp, created_at
		FROM storyline_events
		WHERE story_id = ?
		ORDER BY timestamp ASC
		LIMIT ? OFFSET ?
	`, storyID, pageSize, (page-1)*pageSize)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	events := make([]model.StorylineEvent, 0, pageSize)
	for rows.Next() {
		var (
			id        uint64
			storyID2  string
			hostID    string
			dataType  int32
			eventType string
			pid       string
			exe       string
			detail    string
			ruleName  string
			severity  string
			ts        time.Time
			ct        time.Time
		)
		if err := rows.Scan(&id, &storyID2, &hostID, &dataType, &eventType,
			&pid, &exe, &detail, &ruleName, &severity, &ts, &ct); err != nil {
			return 0, nil, err
		}
		events = append(events, model.StorylineEvent{
			ID:        uint(id),
			StoryID:   storyID2,
			HostID:    hostID,
			DataType:  dataType,
			EventType: eventType,
			PID:       pid,
			Exe:       exe,
			Detail:    detail,
			RuleName:  ruleName,
			Severity:  severity,
			Timestamp: model.LocalTime(ts),
			CreatedAt: model.LocalTime(ct),
		})
	}
	return int64(total), events, rows.Err()
}

// ResolveStoryline 标记故事线为已处理
func (h *StorylineHandler) ResolveStoryline(c *gin.Context) {
	storyID := c.Param("story_id")

	result := h.db.Model(&model.Storyline{}).
		Where("story_id = ?", storyID).
		Updates(map[string]any{
			"status":      "resolved",
			"resolved_by": c.GetString("username"),
		})
	if result.RowsAffected == 0 {
		NotFound(c, "故事线不存在")
		return
	}
	SuccessMessage(c, "故事线已标记为已处理")
}

// GetStorylineStats 故事线统计概览
func (h *StorylineHandler) GetStorylineStats(c *gin.Context) {
	var total, active, critical int64

	h.db.Model(&model.Storyline{}).Count(&total)
	h.db.Model(&model.Storyline{}).Where("status = ?", "active").Count(&active)
	h.db.Model(&model.Storyline{}).Where("severity = ? AND status = ?", "critical", "active").Count(&critical)

	Success(c, gin.H{
		"total":           total,
		"active":          active,
		"critical_active": critical,
	})
}
