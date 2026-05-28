package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ListEvents GET /api/v1/remediation-tasks/:id/events
// 返回指定 task 的全量 lifecycle events，按 sequence 升序。
func (h *RemediationTasksHandler) ListEvents(c *gin.Context) {
	taskID := c.Param("id")
	var events []model.RemediationTaskEvent
	if err := h.db.Where("task_id = ?", taskID).
		Order("sequence ASC").
		Find(&events).Error; err != nil {
		InternalError(c, "查询事件失败")
		return
	}
	Success(c, events)
}

// StreamEvents GET /api/v1/remediation-tasks/:id/events/stream
// SSE 实时推送 lifecycle events，UI 订阅显示 11 state 实时转换。
//
// 客户端约定：
//   - text/event-stream 协议
//   - 每条 event 形如 data: {json}\n\n
//   - heartbeat 每 30s 发 `:` 注释行保持连接
//   - 连接超时 5 分钟（防泄漏，UI 自动重连）
func (h *RemediationTasksHandler) StreamEvents(c *gin.Context) {
	taskIDStr := c.Param("id")
	taskID, err := strconv.ParseUint(taskIDStr, 10, 64)
	if err != nil {
		BadRequest(c, "invalid task id")
		return
	}

	// 先确认 task 存在 + 鉴权（已由 Auth middleware 处理）
	var task model.RemediationTask
	if err := h.db.First(&task, taskID).Error; err != nil {
		NotFound(c, "task 不存在")
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // 禁 nginx buffer
	c.Writer.Flush()

	// 推送已存在 events（sequence ASC）
	var lastSeq uint
	var existing []model.RemediationTaskEvent
	h.db.Where("task_id = ?", taskID).Order("sequence ASC").Find(&existing)
	for _, ev := range existing {
		if err := writeSSEEvent(c.Writer, ev); err != nil {
			return
		}
		lastSeq = ev.Sequence
	}

	// 轮询新 events（生产应替换为 PubSub，简化版用 1s tick）
	const tickInterval = 1 * time.Second
	const maxDuration = 5 * time.Minute
	const heartbeatInterval = 30 * time.Second

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	deadline := time.After(maxDuration)

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-deadline:
			fmt.Fprintf(c.Writer, ": stream timeout, please reconnect\n\n")
			c.Writer.Flush()
			return
		case <-heartbeat.C:
			fmt.Fprintf(c.Writer, ": heartbeat\n\n")
			c.Writer.Flush()
		case <-ticker.C:
			var newEvents []model.RemediationTaskEvent
			h.db.Where("task_id = ? AND sequence > ?", taskID, lastSeq).
				Order("sequence ASC").
				Find(&newEvents)
			for _, ev := range newEvents {
				if err := writeSSEEvent(c.Writer, ev); err != nil {
					return
				}
				lastSeq = ev.Sequence
			}
			// task 已终态 → 关闭流
			if isRemTerminalStatus(task.Status) {
				h.db.First(&task, taskID) // refresh
				if isRemTerminalStatus(task.Status) {
					fmt.Fprintf(c.Writer, "data: {\"event\":\"task_finished\",\"status\":%q}\n\n", task.Status)
					c.Writer.Flush()
					return
				}
			}
		}
	}
}

func writeSSEEvent(w io.Writer, ev model.RemediationTaskEvent) error {
	payload := fmt.Sprintf(
		`{"id":%d,"task_id":%d,"sequence":%d,"stage":%q,"message":%q,"detail":%q,"source":%q,"created_at":%q}`,
		ev.ID, ev.TaskID, ev.Sequence, ev.Stage, ev.Message, ev.Detail, ev.Source,
		time.Time(ev.CreatedAt).Format(time.RFC3339),
	)
	_, err := fmt.Fprintf(w, "id: %d\nevent: progress\ndata: %s\n\n", ev.Sequence, payload)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return err
}

func isRemTerminalStatus(s string) bool {
	switch s {
	case model.RemTaskStatusCompleted,
		model.RemTaskStatusFailed,
		model.RemTaskStatusRolledBack:
		return true
	}
	return false
}
