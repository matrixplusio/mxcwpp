package api

import (
	"context"
	"fmt"
	"strconv"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// FIMEventsHandler FIM 事件处理器
type FIMEventsHandler struct {
	db     *gorm.DB
	chConn chdriver.Conn // 可为 nil，nil 时 fallback MySQL
	logger *zap.Logger
}

// NewFIMEventsHandler 创建 FIM 事件处理器
// chConn 可为 nil；为 nil 时退化为纯 MySQL 查询
func NewFIMEventsHandler(db *gorm.DB, logger *zap.Logger, chConn chdriver.Conn) *FIMEventsHandler {
	return &FIMEventsHandler{db: db, chConn: chConn, logger: logger}
}

// chFIMEvent ClickHouse fim_events 行映射结构
type chFIMEvent struct {
	Timestamp  time.Time `json:"detected_at"`
	HostID     string    `json:"host_id"`
	Hostname   string    `json:"hostname"`
	FilePath   string    `json:"file_path"`
	ChangeType string    `json:"change_type"`
	Severity   string    `json:"severity"`
	Category   string    `json:"category"`
	Detail     string    `json:"detail"`
	TraceID    string    `json:"trace_id"`
}

// ListFIMEvents 获取 FIM 事件列表
// ClickHouse 可用时优先从 CH 查询（低延迟、支持大数据量）；否则 fallback MySQL
func (h *FIMEventsHandler) ListFIMEvents(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	if h.chConn != nil {
		h.listFIMEventsFromCH(c, page, pageSize)
		return
	}
	h.listFIMEventsFromMySQL(c, page, pageSize)
}

// listFIMEventsFromCH 从 ClickHouse fim_events 表查询
func (h *FIMEventsHandler) listFIMEventsFromCH(c *gin.Context, page, pageSize int) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// 构建 WHERE 子句
	where := "1=1"
	args := []interface{}{}

	if hostID := c.Query("host_id"); hostID != "" {
		where += " AND host_id = ?"
		args = append(args, hostID)
	}
	if hostname := c.Query("hostname"); hostname != "" {
		where += " AND hostname LIKE ?"
		args = append(args, "%"+hostname+"%")
	}
	if filePath := c.Query("file_path"); filePath != "" {
		where += " AND file_path LIKE ?"
		args = append(args, "%"+filePath+"%")
	}
	if changeType := c.Query("change_type"); changeType != "" {
		where += " AND change_type = ?"
		args = append(args, changeType)
	}
	if severity := c.Query("severity"); severity != "" {
		where += " AND severity = ?"
		args = append(args, severity)
	}
	if category := c.Query("category"); category != "" {
		where += " AND category = ?"
		args = append(args, category)
	}
	if status := c.Query("status"); status != "" {
		where += " AND status = ?"
		args = append(args, status)
	}
	if dateFrom := c.Query("date_from"); dateFrom != "" {
		where += " AND timestamp >= ?"
		args = append(args, dateFrom)
	}
	if dateTo := c.Query("date_to"); dateTo != "" {
		where += " AND timestamp <= ?"
		args = append(args, dateTo+" 23:59:59")
	}

	// 查总数
	countSQL := fmt.Sprintf("SELECT count() FROM fim_events WHERE %s", where)
	var total uint64
	if err := h.chConn.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		h.logger.Warn("ClickHouse 查询 FIM 事件总数失败，fallback MySQL", zap.Error(err))
		h.listFIMEventsFromMySQL(c, page, pageSize)
		return
	}
	// CH count=0 也 fallback MySQL：consumer 可能只写 MySQL（双写未配置）
	// 避免 UI stats 有数（MySQL）但 list 空（CH）的不一致
	if total == 0 {
		h.listFIMEventsFromMySQL(c, page, pageSize)
		return
	}

	// 查数据
	offset := (page - 1) * pageSize
	dataSQL := fmt.Sprintf(`
		SELECT timestamp, host_id, hostname, file_path, change_type, severity, category, detail, trace_id
		FROM fim_events
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d OFFSET %d`, where, pageSize, offset)

	rows, err := h.chConn.Query(ctx, dataSQL, args...)
	if err != nil {
		h.logger.Warn("ClickHouse 查询 FIM 事件列表失败，fallback MySQL", zap.Error(err))
		h.listFIMEventsFromMySQL(c, page, pageSize)
		return
	}
	defer rows.Close()

	events := make([]chFIMEvent, 0, pageSize)
	for rows.Next() {
		var ev chFIMEvent
		if err := rows.Scan(
			&ev.Timestamp, &ev.HostID, &ev.Hostname, &ev.FilePath,
			&ev.ChangeType, &ev.Severity, &ev.Category, &ev.Detail, &ev.TraceID,
		); err != nil {
			continue
		}
		events = append(events, ev)
	}

	SuccessPaginated(c, int64(total), events)
}

// listFIMEventsFromMySQL fallback：从 MySQL 查询
func (h *FIMEventsHandler) listFIMEventsFromMySQL(c *gin.Context, page, pageSize int) {
	query := h.db.Model(&model.FIMEvent{})

	if hostID := c.Query("host_id"); hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if hostname := c.Query("hostname"); hostname != "" {
		query = query.Where("hostname LIKE ?", "%"+hostname+"%")
	}
	if filePath := c.Query("file_path"); filePath != "" {
		query = query.Where("file_path LIKE ?", "%"+filePath+"%")
	}
	if changeType := c.Query("change_type"); changeType != "" {
		query = query.Where("change_type = ?", changeType)
	}
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if category := c.Query("category"); category != "" {
		query = query.Where("category = ?", category)
	}
	if taskID := c.Query("task_id"); taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if status := c.Query("status"); status != "" {
		query = query.Where("status = ?", status)
	}
	if dateFrom := c.Query("date_from"); dateFrom != "" {
		query = query.Where("detected_at >= ?", dateFrom)
	}
	if dateTo := c.Query("date_to"); dateTo != "" {
		query = query.Where("detected_at <= ?", dateTo+" 23:59:59")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询 FIM 事件总数失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	var events []model.FIMEvent
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("detected_at DESC").Find(&events).Error; err != nil {
		h.logger.Error("查询 FIM 事件列表失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	SuccessPaginated(c, total, events)
}

// GetFIMEvent 获取单个 FIM 事件详情（始终走 MySQL，CH 无主键 event_id）
func (h *FIMEventsHandler) GetFIMEvent(c *gin.Context) {
	eventID := c.Param("id")

	var event model.FIMEvent
	if err := h.db.Where("event_id = ?", eventID).First(&event).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "事件不存在")
			return
		}
		h.logger.Error("查询 FIM 事件失败", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, event)
}

// FIMEventStats FIM 事件统计响应
type FIMEventStats struct {
	Total    int64 `json:"total"`
	Pending  int64 `json:"pending"`
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	// 按变更类型统计
	Added   int64 `json:"added"`
	Removed int64 `json:"removed"`
	Changed int64 `json:"changed"`
	// 按分类统计
	ByCategory map[string]int64 `json:"by_category"`
	// Top 主机
	TopHosts []FIMHostEventCount `json:"top_hosts"`
	// 趋势数据
	Trend []FIMEventTrendPoint `json:"trend"`
}

// FIMHostEventCount 主机事件数统计
type FIMHostEventCount struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Count    int64  `json:"count"`
}

// FIMEventTrendPoint 事件趋势数据点
type FIMEventTrendPoint struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// GetFIMEventStats 获取 FIM 事件统计
// ClickHouse 可用时从 CH 查询（支持大数据量聚合）；否则 fallback MySQL
func (h *FIMEventsHandler) GetFIMEventStats(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days < 1 || days > 90 {
		days = 7
	}

	if h.chConn != nil {
		h.getFIMEventStatsFromCH(c, days)
		return
	}
	h.getFIMEventStatsFromMySQL(c, days)
}

// getFIMEventStatsFromCH 从 ClickHouse 聚合 FIM 事件统计
func (h *FIMEventsHandler) getFIMEventStatsFromCH(c *gin.Context, days int) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	stats := FIMEventStats{ByCategory: make(map[string]int64)}

	// 1. 总数 + 按 severity/change_type 统计（单次查询）
	rows, err := h.chConn.Query(ctx, `
		SELECT
			count()                                        AS total,
			countIf(severity = 'critical')                AS critical,
			countIf(severity = 'high')                    AS high,
			countIf(severity = 'medium')                  AS medium,
			countIf(severity = 'low')                     AS low,
			countIf(change_type = 'added')                AS added,
			countIf(change_type = 'removed')              AS removed,
			countIf(change_type = 'changed')              AS changed
		FROM fim_events
		WHERE timestamp >= subtractDays(now(), ?)`, days)
	if err != nil {
		h.logger.Warn("ClickHouse FIM 统计查询失败，fallback MySQL", zap.Error(err))
		h.getFIMEventStatsFromMySQL(c, days)
		return
	}
	if rows.Next() {
		_ = rows.Scan(&stats.Total, &stats.Critical, &stats.High, &stats.Medium, &stats.Low,
			&stats.Added, &stats.Removed, &stats.Changed)
	}
	rows.Close()

	// ClickHouse 表存在但无数据（FIM 事件仅写 MySQL），fallback MySQL
	if stats.Total == 0 {
		h.getFIMEventStatsFromMySQL(c, days)
		return
	}

	// 2. 按分类统计
	catRows, err := h.chConn.Query(ctx, `
		SELECT category, count() AS cnt
		FROM fim_events
		WHERE timestamp >= subtractDays(now(), ?) AND category != ''
		GROUP BY category`, days)
	if err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var cat string
			var cnt int64
			if scanErr := catRows.Scan(&cat, &cnt); scanErr == nil {
				stats.ByCategory[cat] = cnt
			}
		}
	}

	// 3. Top 10 主机
	hostRows, err := h.chConn.Query(ctx, `
		SELECT host_id, hostname, count() AS cnt
		FROM fim_events
		WHERE timestamp >= subtractDays(now(), ?)
		GROUP BY host_id, hostname
		ORDER BY cnt DESC
		LIMIT 10`, days)
	if err == nil {
		defer hostRows.Close()
		for hostRows.Next() {
			var hc FIMHostEventCount
			if scanErr := hostRows.Scan(&hc.HostID, &hc.Hostname, &hc.Count); scanErr == nil {
				stats.TopHosts = append(stats.TopHosts, hc)
			}
		}
	}
	if stats.TopHosts == nil {
		stats.TopHosts = []FIMHostEventCount{}
	}

	// 4. 趋势（按天）
	trendRows, err := h.chConn.Query(ctx, `
		SELECT toString(toDate(timestamp)) AS date, count() AS cnt
		FROM fim_events
		WHERE timestamp >= subtractDays(now(), ?)
		GROUP BY date
		ORDER BY date ASC`, days)
	if err == nil {
		defer trendRows.Close()
		for trendRows.Next() {
			var tp FIMEventTrendPoint
			if scanErr := trendRows.Scan(&tp.Date, &tp.Count); scanErr == nil {
				stats.Trend = append(stats.Trend, tp)
			}
		}
	}
	if stats.Trend == nil {
		stats.Trend = []FIMEventTrendPoint{}
	}

	Success(c, stats)
}

// getFIMEventStatsFromMySQL fallback：从 MySQL 聚合
func (h *FIMEventsHandler) getFIMEventStatsFromMySQL(c *gin.Context, days int) {
	stats := FIMEventStats{
		ByCategory: make(map[string]int64),
	}

	h.db.Model(&model.FIMEvent{}).Count(&stats.Total)
	h.db.Model(&model.FIMEvent{}).Where("status = ?", "pending").Count(&stats.Pending)
	h.db.Model(&model.FIMEvent{}).Where("severity = ?", "critical").Count(&stats.Critical)
	h.db.Model(&model.FIMEvent{}).Where("severity = ?", "high").Count(&stats.High)
	h.db.Model(&model.FIMEvent{}).Where("severity = ?", "medium").Count(&stats.Medium)
	h.db.Model(&model.FIMEvent{}).Where("severity = ?", "low").Count(&stats.Low)
	h.db.Model(&model.FIMEvent{}).Where("change_type = ?", "added").Count(&stats.Added)
	h.db.Model(&model.FIMEvent{}).Where("change_type = ?", "removed").Count(&stats.Removed)
	h.db.Model(&model.FIMEvent{}).Where("change_type = ?", "changed").Count(&stats.Changed)

	type CategoryCount struct {
		Category string `json:"category"`
		Count    int64  `json:"count"`
	}
	var categoryCounts []CategoryCount
	h.db.Model(&model.FIMEvent{}).
		Select("category, COUNT(*) as count").
		Where("category IS NOT NULL AND category != ''").
		Group("category").
		Find(&categoryCounts)
	for _, cc := range categoryCounts {
		stats.ByCategory[cc.Category] = cc.Count
	}

	h.db.Model(&model.FIMEvent{}).
		Select("host_id, hostname, COUNT(*) as count").
		Group("host_id, hostname").
		Order("count DESC").
		Limit(10).
		Find(&stats.TopHosts)
	if stats.TopHosts == nil {
		stats.TopHosts = []FIMHostEventCount{}
	}

	h.db.Model(&model.FIMEvent{}).
		Select("DATE(detected_at) as date, COUNT(*) as count").
		Where("detected_at >= DATE_SUB(NOW(), INTERVAL ? DAY)", days).
		Group("DATE(detected_at)").
		Order("date ASC").
		Find(&stats.Trend)
	if stats.Trend == nil {
		stats.Trend = []FIMEventTrendPoint{}
	}

	Success(c, stats)
}

// ConfirmFIMEventRequest 确认 FIM 事件请求
type ConfirmFIMEventRequest struct {
	Reason         string `json:"reason"`
	UpdateBaseline bool   `json:"update_baseline"`
}

// ConfirmFIMEvent 确认 FIM 事件为合法变更
func (h *FIMEventsHandler) ConfirmFIMEvent(c *gin.Context) {
	eventID := c.Param("id")
	username, _ := c.Get("username")

	var req ConfirmFIMEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数错误")
		return
	}

	var event model.FIMEvent
	if err := h.db.Where("event_id = ?", eventID).First(&event).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "事件不存在")
			return
		}
		InternalError(c, "查询失败")
		return
	}

	if event.Status != "pending" {
		BadRequest(c, "仅待确认的事件可以确认")
		return
	}

	now := model.Now()
	if err := h.db.Model(&event).Updates(map[string]any{
		"status":         "confirmed",
		"confirmed_by":   username,
		"confirmed_at":   &now,
		"confirm_reason": req.Reason,
	}).Error; err != nil {
		h.logger.Error("确认 FIM 事件失败", zap.Error(err))
		InternalError(c, "确认失败")
		return
	}

	Success(c, gin.H{"message": "事件已确认"})
}

// BatchConfirmFIMEvents 批量确认 FIM 事件
func (h *FIMEventsHandler) BatchConfirmFIMEvents(c *gin.Context) {
	var req struct {
		EventIDs []string `json:"event_ids" binding:"required"`
		Reason   string   `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.EventIDs) == 0 {
		BadRequest(c, "请提供事件 ID 列表")
		return
	}

	username, _ := c.Get("username")
	now := model.Now()

	result := h.db.Model(&model.FIMEvent{}).
		Where("event_id IN ? AND status = ?", req.EventIDs, "pending").
		Updates(map[string]any{
			"status":         "confirmed",
			"confirmed_by":   username,
			"confirmed_at":   &now,
			"confirm_reason": req.Reason,
		})

	if result.Error != nil {
		h.logger.Error("批量确认 FIM 事件失败", zap.Error(result.Error))
		InternalError(c, "批量确认失败")
		return
	}

	Success(c, gin.H{"confirmed": result.RowsAffected})
}
