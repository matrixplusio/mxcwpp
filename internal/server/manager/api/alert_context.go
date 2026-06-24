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

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// AlertContextHandler 告警溯源上下文 API 处理器
type AlertContextHandler struct {
	db     *gorm.DB
	chConn chdriver.Conn
	logger *zap.Logger
}

// NewAlertContextHandler 创建告警溯源处理器
func NewAlertContextHandler(db *gorm.DB, chConn chdriver.Conn, logger *zap.Logger) *AlertContextHandler {
	return &AlertContextHandler{db: db, chConn: chConn, logger: logger}
}

// timelineEvent 时间线事件
type timelineEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"eventType"`
	Source    string `json:"source"` // ebpf, fim, scanner
	Detail    string `json:"detail"`
	PID       string `json:"pid,omitempty"`
	Exe       string `json:"exe,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	FilePath  string `json:"filePath,omitempty"`
}

// processNode 进程树节点
type processNode struct {
	PID       string         `json:"pid"`
	PPID      string         `json:"ppid"`
	Exe       string         `json:"exe"`
	Cmdline   string         `json:"cmdline"`
	Timestamp string         `json:"timestamp"`
	Children  []*processNode `json:"children,omitempty"`
}

// networkConn 网络连接
type networkConn struct {
	Timestamp  string `json:"timestamp"`
	RemoteAddr string `json:"remoteAddr"`
	RemotePort string `json:"remotePort"`
	Protocol   string `json:"protocol"`
	PID        string `json:"pid"`
	Exe        string `json:"exe"`
}

// GetAlertContext 获取告警溯源上下文
// GET /api/v1/alerts/:id/context
func (h *AlertContextHandler) GetAlertContext(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		BadRequest(c, "无效的告警 ID")
		return
	}

	// 查询告警
	var alert model.Alert
	if err := h.db.First(&alert, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "告警不存在")
			return
		}
		InternalError(c, "查询告警失败")
		return
	}

	// 时间窗口：告警前后 30 分钟
	alertTime := time.Time(alert.FirstSeenAt)
	startTime := alertTime.Add(-30 * time.Minute)
	endTime := alertTime.Add(30 * time.Minute)

	var timeline []timelineEvent
	var processes []*processNode
	var connections []networkConn

	// 如果 ClickHouse 可用，查询 eBPF 和 FIM 事件
	if h.chConn != nil {
		timeline, processes, connections = h.queryClickHouseContext(alert.HostID, startTime, endTime)
	}

	// 补充 FIM 事件（从 MySQL）
	fimEvents := h.queryFIMEvents(alert.HostID, startTime, endTime)
	timeline = append(timeline, fimEvents...)

	// 按时间排序
	sortTimeline(timeline)

	Success(c, gin.H{
		"alert":        alert,
		"timeline":     timeline,
		"processTree":  processes,
		"networkConns": connections,
		"timeRange": gin.H{
			"start": startTime.Format(model.TimeFormat),
			"end":   endTime.Format(model.TimeFormat),
		},
	})
}

// queryClickHouseContext 从 ClickHouse 查询 eBPF 事件上下文
func (h *AlertContextHandler) queryClickHouseContext(hostID string, start, end time.Time) ([]timelineEvent, []*processNode, []networkConn) {
	ctx := context.Background()
	var timeline []timelineEvent
	var processes []*processNode
	var connections []networkConn

	// 查询 eBPF 事件
	rows, err := h.chConn.Query(ctx,
		`SELECT timestamp, event_type, pid, ppid, exe, cmdline, parent_exe, file_path, remote_addr, remote_port, protocol
		 FROM ebpf_events
		 WHERE host_id = ? AND timestamp >= ? AND timestamp <= ?
		 ORDER BY timestamp ASC
		 LIMIT 500`,
		hostID, start, end)
	if err != nil {
		h.logger.Warn("查询 ClickHouse ebpf_events 失败", zap.Error(err))
		return timeline, processes, connections
	}
	defer rows.Close()

	processMap := make(map[string]*processNode)

	for rows.Next() {
		var ts time.Time
		var eventType, pid, ppid, exe, cmdline, parentExe, filePath, remoteAddr, remotePort, protocol string

		if err := rows.Scan(&ts, &eventType, &pid, &ppid, &exe, &cmdline, &parentExe, &filePath, &remoteAddr, &remotePort, &protocol); err != nil {
			continue
		}

		// 时间线事件
		detail := fmt.Sprintf("[%s] %s", eventType, exe)
		if cmdline != "" {
			detail += " " + cmdline
		}
		if filePath != "" {
			detail += " → " + filePath
		}
		if remoteAddr != "" {
			detail += fmt.Sprintf(" → %s:%s", remoteAddr, remotePort)
		}

		timeline = append(timeline, timelineEvent{
			Timestamp: ts.Format(model.TimeFormat),
			EventType: eventType,
			Source:    "ebpf",
			Detail:    detail,
			PID:       pid,
			Exe:       exe,
			Cmdline:   cmdline,
			FilePath:  filePath,
		})

		// 构建进程树
		if eventType == "process_exec" && pid != "" {
			node := &processNode{
				PID:       pid,
				PPID:      ppid,
				Exe:       exe,
				Cmdline:   cmdline,
				Timestamp: ts.Format(model.TimeFormat),
			}
			processMap[pid] = node
		}

		// 收集网络连接
		if remoteAddr != "" {
			connections = append(connections, networkConn{
				Timestamp:  ts.Format(model.TimeFormat),
				RemoteAddr: remoteAddr,
				RemotePort: remotePort,
				Protocol:   protocol,
				PID:        pid,
				Exe:        exe,
			})
		}
	}

	// 组装进程树
	for _, node := range processMap {
		if parent, ok := processMap[node.PPID]; ok {
			parent.Children = append(parent.Children, node)
		} else {
			processes = append(processes, node)
		}
	}

	return timeline, processes, connections
}

// queryFIMEvents 从 MySQL 查询 FIM 事件
func (h *AlertContextHandler) queryFIMEvents(hostID string, start, end time.Time) []timelineEvent {
	var events []model.FIMEvent
	h.db.Where("host_id = ? AND detected_at BETWEEN ? AND ?", hostID, start, end).
		Order("detected_at ASC").
		Limit(100).
		Find(&events)

	var timeline []timelineEvent
	for _, e := range events {
		timeline = append(timeline, timelineEvent{
			Timestamp: time.Time(e.DetectedAt).Format(model.TimeFormat),
			EventType: e.ChangeType,
			Source:    "fim",
			Detail:    fmt.Sprintf("[FIM] %s: %s", e.ChangeType, e.FilePath),
			FilePath:  e.FilePath,
		})
	}
	return timeline
}

// sortTimeline 按时间排序
func sortTimeline(events []timelineEvent) {
	for i := 1; i < len(events); i++ {
		for j := i; j > 0 && events[j].Timestamp < events[j-1].Timestamp; j-- {
			events[j], events[j-1] = events[j-1], events[j]
		}
	}
}
