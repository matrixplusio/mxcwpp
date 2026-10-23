package api

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// authEvent 认证事件（数据源：ClickHouse auth_events）。
type authEvent struct {
	Timestamp   time.Time `ch:"timestamp" json:"timestamp"`
	HostID      string    `ch:"host_id" json:"host_id"`
	Hostname    string    `ch:"hostname" json:"hostname"`
	EventType   string    `ch:"event_type" json:"event_type"`
	Service     string    `ch:"service" json:"service"`
	Trust       string    `ch:"trust" json:"trust"`
	Username    string    `ch:"username" json:"username"`
	TargetUser  string    `ch:"target_user" json:"target_user"`
	SourceIP    string    `ch:"source_ip" json:"source_ip"`
	SourcePort  string    `ch:"source_port" json:"source_port"`
	AuthMethod  string    `ch:"auth_method" json:"auth_method"`
	KeyFP       string    `ch:"key_fingerprint" json:"key_fingerprint"`
	Reason      string    `ch:"reason" json:"reason"`
	InvalidUser uint8     `ch:"invalid_user" json:"invalid_user"`
	TTY         string    `ch:"tty" json:"tty"`
	Cwd         string    `ch:"cwd" json:"cwd"`
	Command     string    `ch:"command" json:"command"`
	Detail      string    `ch:"detail" json:"detail"`
	PID         string    `ch:"pid" json:"pid"`
	Count       uint32    `ch:"count" json:"count"`
	Raw         string    `ch:"raw" json:"raw"`
	// ReceivedAt AgentCenter 收到这条记录的时间。timestamp 是主机报的，主机时钟可以被改。
	ReceivedAt time.Time `ch:"received_at" json:"received_at"`
}

// authEventTypes 允许按其筛选的事件类型。
var authEventTypes = map[string]bool{
	"auth_login_success": true, "auth_login_failed": true, "auth_preauth_close": true,
	"auth_session_open": true, "auth_session_close": true,
	"auth_sudo": true, "auth_sudo_denied": true, "auth_su_success": true, "auth_su_failed": true,
	"auth_account_change": true, "auth_collector_stats": true, "auth_collector_heartbeat": true,
}

const (
	authEventsMaxPageSize = 200
	// authEventsMaxOffset 翻页深度上限。再往后翻的需求应当靠缩小时间范围或加筛选条件解决，
	// 而不是让 ClickHouse 排序后丢掉大量行。
	authEventsMaxOffset = 10000
)

// maskAttemptedUsername 遮掉「本机不存在的账号」的大部分内容。
//
// 有人会把密码错输进用户名一栏，它就以「不存在的账号」的形式留在登录失败的记录里。
// 本机存在的账号名不是秘密，原样显示；不存在的只留开头，够认出 admin、test 这类爆破用名即可。
func maskAttemptedUsername(e *authEvent) {
	if e.InvalidUser != 1 || (e.EventType != "auth_login_failed" && e.EventType != "auth_preauth_close") {
		return
	}
	r := []rune(e.Username)
	if len(r) > 2 {
		e.Username = string(r[:2]) + "***"
	}
	// 原文里有同一个用户名的全文。
	e.Raw = ""
}

// ListAuthEvents 查询认证事件。
//
// GET /api/v1/edr/auth-events
func (h *EDREventsHandler) ListAuthEvents(c *gin.Context) {
	if h.chConn == nil {
		SuccessPaginated(c, 0, []authEvent{})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > authEventsMaxPageSize {
		pageSize = 20
	}
	offset := (page - 1) * pageSize
	if offset > authEventsMaxOffset {
		BadRequest(c, "翻页过深，请缩小时间范围或增加筛选条件")
		return
	}

	where := "1=1"
	args := []interface{}{}
	dateFrom, dateTo := c.Query("date_from"), c.Query("date_to")
	if dateFrom == "" && dateTo == "" {
		dateFrom = time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	}
	if v := c.Query("host_id"); v != "" {
		where += " AND host_id = ?"
		args = append(args, v)
	}
	if v := c.Query("hostname"); v != "" {
		where += " AND hostname LIKE ?"
		args = append(args, "%"+v+"%")
	}
	if v := c.Query("event_type"); v != "" {
		if !authEventTypes[v] {
			BadRequest(c, "无效的事件类型")
			return
		}
		where += " AND event_type = ?"
		args = append(args, v)
	} else {
		// 采集心跳每台主机每 5 分钟一条，不筛类型时会把登录记录淹掉；要看就按类型筛。
		where += " AND event_type != 'auth_collector_heartbeat'"
	}
	if v := c.Query("username"); v != "" {
		where += " AND (username = ? OR target_user = ?)"
		args = append(args, v, v)
	}
	if v := c.Query("source_ip"); v != "" {
		where += " AND source_ip = ?"
		args = append(args, v)
	}
	if v := c.Query("keyword"); v != "" {
		where += " AND (command LIKE ? OR detail LIKE ?)"
		kw := "%" + v + "%"
		args = append(args, kw, kw)
	}
	if dateFrom != "" {
		where += " AND timestamp >= ?"
		args = append(args, normalizeDateBound(dateFrom, false))
	}
	if dateTo != "" {
		where += " AND timestamp <= ?"
		args = append(args, normalizeDateBound(dateTo, true))
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), edrQueryCtxTimeout)
	defer cancel()

	// where 只由上面的固定片段拼成，用户输入全部走参数；分页的两个数是校验过范围的整数。
	countSQL := "SELECT count() FROM auth_events WHERE " + where
	dataSQL := fmt.Sprintf(`
		SELECT timestamp, host_id, hostname, event_type, service, trust, username, target_user,
		       source_ip, source_port, auth_method, key_fingerprint, reason, invalid_user,
		       tty, cwd, command, detail, pid, count, raw, received_at
		FROM auth_events
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d OFFSET %d`, where, pageSize, offset)

	var total uint64
	events := make([]authEvent, 0, pageSize)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return h.chConn.QueryRow(chQueryCtx(gctx), countSQL, args...).Scan(&total) })
	g.Go(func() error { return h.chConn.Select(chQueryCtx(gctx), &events, dataSQL, args...) })
	if err := g.Wait(); err != nil {
		h.logger.Error("查询认证事件失败", zap.Error(err))
		InternalError(c, "查询认证事件失败")
		return
	}
	for i := range events {
		maskAttemptedUsername(&events[i])
	}
	SuccessPaginated(c, int64(total), events)
}
