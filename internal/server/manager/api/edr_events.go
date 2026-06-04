package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/imkerbos/mxsec-platform/internal/server/metrics"
)

// EDR 查询端到端超时策略：
//
//   - Go 端 context 超时:  edrQueryCtxTimeout = 60s  (HTTP handler 上限)
//   - CH 端 max_execution_time: 50s                  (比 Go 端早 10s 停，让 CH 主动报错而非 Go 端取消)
//   - 慢查询告警阈值:        3s                       (>3s 走 Warn 日志 + Prom 慢查询桶)
//
// 商业 EDR 列表查询正常路径在 Projection 命中后 < 200ms；保留 60s 上限是为大窗口/复杂过滤兜底，
// 避免一刀切 10s 把合法慢查询误杀。最终失败仍要明确返回 500 + 引导用户缩窄时间范围。
const (
	edrQueryCtxTimeout = 60 * time.Second
	edrCHMaxExec       = 50 // 秒
	edrSlowQueryThresh = 3 * time.Second
)

// EDREventsHandler EDR 事件查询处理器（数据源：ClickHouse ebpf_events）
type EDREventsHandler struct {
	chConn chdriver.Conn
	logger *zap.Logger
}

// NewEDREventsHandler 创建 EDR 事件处理器
// chConn 为 nil 时返回空数据（EDR 事件仅存储在 ClickHouse）
func NewEDREventsHandler(logger *zap.Logger, chConn chdriver.Conn) *EDREventsHandler {
	return &EDREventsHandler{chConn: chConn, logger: logger}
}

// chEDREvent ClickHouse ebpf_events 行映射
type chEDREvent struct {
	Timestamp  time.Time `json:"timestamp"`
	HostID     string    `json:"host_id"`
	Hostname   string    `json:"hostname"`
	EventType  string    `json:"event_type"`
	DataType   int32     `json:"data_type"`
	PID        string    `json:"pid"`
	PPID       string    `json:"ppid"`
	Exe        string    `json:"exe"`
	Cmdline    string    `json:"cmdline"`
	ParentExe  string    `json:"parent_exe"`
	FilePath   string    `json:"file_path"`
	RemoteAddr string    `json:"remote_addr"`
	RemotePort string    `json:"remote_port"`
	LocalAddr  string    `json:"local_addr"`
	LocalPort  string    `json:"local_port"`
	Protocol   string    `json:"protocol"`
	UID        string    `json:"uid"`
	GID        string    `json:"gid"`
	ReturnCode string    `json:"return_code"`
}

// chQueryCtx 给 ClickHouse 查询附加 max_execution_time 兜底超时 + 强制使用 projection。
//
// CH 24.10 cost-based optimizer 在 SELECT 列宽 + LIMIT 较大时不一定自动选 projection,
// 实测 prod 19 列 LIMIT 50:
//   - 不强制 projection: 10s 超时（全 part 排序）
//   - force_optimize_projection=1: 4.4s（走 proj_time_desc 主键反向）
//
// 实际差距来自 cost 估算偏保守。手工强制后查询稳定走 projection 快路径。
// 副作用:若用户 query 无对应 projection（如 GROUP BY host_id 类）会直接报错 → 由 recordCHQuery 捕获。
func chQueryCtx(parent context.Context) context.Context {
	return clickhouse.Context(parent, clickhouse.WithSettings(clickhouse.Settings{
		"max_execution_time":       edrCHMaxExec,
		"optimize_use_projections": uint64(1),
	}))
}

// chQueryCtxWithProjection 仅给 list_data 这种"我知道 projection 一定能命中"的查询用,
// 强制走 projection。stats/聚合类继续走默认 optimize_use_projections 让 CH 自决策。
func chQueryCtxWithProjection(parent context.Context) context.Context {
	return clickhouse.Context(parent, clickhouse.WithSettings(clickhouse.Settings{
		"max_execution_time":        edrCHMaxExec,
		"optimize_use_projections":  uint64(1),
		"force_optimize_projection": uint64(1),
	}))
}

// recordCHQuery 记录 ClickHouse 查询延迟到 Prom + 慢查询告警日志。
func (h *EDREventsHandler) recordCHQuery(op, table string, start time.Time, err error) {
	dur := time.Since(start)
	status := "ok"
	if err != nil {
		status = "error"
		// CH max_execution_time / Go ctx deadline 都归为 timeout
		msg := err.Error()
		if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "max_execution_time") || strings.Contains(msg, "TIMEOUT_EXCEEDED") {
			status = "timeout"
		}
	}
	metrics.RecordCHQueryDuration(op, table, status, dur.Seconds())
	if dur >= edrSlowQueryThresh {
		h.logger.Warn("ClickHouse 慢查询",
			zap.String("op", op),
			zap.String("table", table),
			zap.String("status", status),
			zap.Duration("duration", dur),
		)
	}
}

// normalizeDateBound 把日期/datetime 字符串规整为 ClickHouse 可比较的 DateTime 字符串。
//
// 兼容格式:
//   - "2026-06-04"                -> "2026-06-04 00:00:00" (upper=false) / "2026-06-04 23:59:59" (upper=true)
//   - "2026-06-04 15:30:45"       -> 原样
//   - "2026-06-04T15:30:45Z"      -> "2026-06-04 15:30:45"  (ISO 8601,兼容前端 dayjs().toISOString())
//   - "2026-06-04T15:30:45+08:00" -> "2026-06-04 15:30:45"  (剥时区)
//
// ClickHouse DateTime64 解析要求空格分隔无时区,严格不接受 "T" 或 "Z"/"+HH:MM"。
func normalizeDateBound(s string, upper bool) string {
	if s == "" {
		return s
	}
	// ISO 8601: 把 'T' 替换为空格
	if strings.Contains(s, "T") {
		s = strings.Replace(s, "T", " ", 1)
	}
	// 剥末尾 Z 时区
	s = strings.TrimSuffix(s, "Z")
	// 剥 +HH:MM / -HH:MM 时区 (扫描 "10" 长度日期之后的 +/-)
	if idx := strings.LastIndexAny(s, "+-"); idx > 10 {
		if (len(s)-idx) >= 5 && s[idx+1] >= '0' && s[idx+1] <= '9' {
			s = s[:idx]
		}
	}
	s = strings.TrimSpace(s)
	// 仅日期(无 ':')补时分秒
	if !strings.Contains(s, ":") {
		if upper {
			return s + " 23:59:59"
		}
		return s + " 00:00:00"
	}
	return s
}

// ListEDREvents 获取 EDR 事件列表
// GET /api/v1/edr/events
func (h *EDREventsHandler) ListEDREvents(c *gin.Context) {
	if h.chConn == nil {
		SuccessPaginated(c, 0, []chEDREvent{})
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 20
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), edrQueryCtxTimeout)
	defer cancel()

	// 构建 WHERE 子句
	//
	// 默认时间窗：date_from / date_to 都未传时，自动加 last 24h。
	// ebpf_events 表 PARTITION BY YYYYMMDD(timestamp)，无时间过滤会扫全部 part →
	// 配合 proj_time_desc projection 才能保证 ORDER BY timestamp DESC LIMIT N 走主键反向扫描。
	where := "1=1"
	args := []interface{}{}

	dateFrom := c.Query("date_from")
	dateTo := c.Query("date_to")
	if dateFrom == "" && dateTo == "" {
		// 默认 24h：用精确时分秒，让 CH 命中 partition 裁剪 + projection 反向主键
		dateFrom = time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	}

	// hasHostID 控制是否强制 projection:
	// - 有 host_id: 主键 (host_id, timestamp) 反向就够快,不强制 projection(force 时会因 projection 无 host_id index 而 fail)
	// - 无 host_id: 强制走 proj_time_desc projection 主键反向,避开 cost-based 估算偏保守
	hasHostID := false
	if hostID := c.Query("host_id"); hostID != "" {
		where += " AND host_id = ?"
		args = append(args, hostID)
		hasHostID = true
	}
	if hostname := c.Query("hostname"); hostname != "" {
		where += " AND hostname LIKE ?"
		args = append(args, "%"+hostname+"%")
	}
	if eventType := c.Query("event_type"); eventType != "" {
		where += " AND event_type = ?"
		args = append(args, eventType)
	}
	if dataType := c.Query("data_type"); dataType != "" {
		dt, err := strconv.Atoi(dataType)
		if err == nil {
			where += " AND data_type = ?"
			args = append(args, int32(dt))
		}
	}
	if exe := c.Query("exe"); exe != "" {
		where += " AND exe LIKE ?"
		args = append(args, "%"+exe+"%")
	}
	if cmdline := c.Query("cmdline"); cmdline != "" {
		where += " AND cmdline LIKE ?"
		args = append(args, "%"+cmdline+"%")
	}
	if filePath := c.Query("file_path"); filePath != "" {
		where += " AND file_path LIKE ?"
		args = append(args, "%"+filePath+"%")
	}
	if remoteAddr := c.Query("remote_addr"); remoteAddr != "" {
		where += " AND remote_addr = ?"
		args = append(args, remoteAddr)
	}
	if pid := c.Query("pid"); pid != "" {
		where += " AND pid = ?"
		args = append(args, pid)
	}
	// 通用关键词搜索（exe/cmdline/file_path）
	if keyword := c.Query("keyword"); keyword != "" {
		where += " AND (exe LIKE ? OR cmdline LIKE ? OR file_path LIKE ?)"
		kw := "%" + keyword + "%"
		args = append(args, kw, kw, kw)
	}
	if dateFrom != "" {
		where += " AND timestamp >= ?"
		args = append(args, normalizeDateBound(dateFrom, false))
	}
	if dateTo != "" {
		where += " AND timestamp <= ?"
		args = append(args, normalizeDateBound(dateTo, true))
	}

	// 根据是否有 host_id 选择 CH ctx:
	// - 有 host_id: 主键 (host_id, timestamp) 已最优,不强制 projection
	// - 无 host_id: 强制 proj_time_desc projection 避开 cost-based 估算偏保守
	dataCtx := chQueryCtx(ctx)
	if !hasHostID {
		dataCtx = chQueryCtxWithProjection(ctx)
	}
	countCtx := chQueryCtx(ctx) // count() 是 metadata,不需强制 projection

	// count + data 并发(errgroup)。count 通常 <100ms,data 可能 100ms-3s,
	// 串行多花 count 时间;并发后总延迟 = max(count, data) ≈ data。
	offset := (page - 1) * pageSize
	countSQL := fmt.Sprintf("SELECT count() FROM ebpf_events WHERE %s", where)
	dataSQL := fmt.Sprintf(`
		SELECT timestamp, host_id, hostname, event_type, data_type,
		       pid, ppid, exe, cmdline, parent_exe,
		       file_path, remote_addr, remote_port, local_addr, local_port,
		       protocol, uid, gid, return_code
		FROM ebpf_events
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d OFFSET %d`, where, pageSize, offset)

	g, _ := errgroup.WithContext(ctx)
	var total uint64
	events := make([]chEDREvent, 0, pageSize)

	g.Go(func() error {
		start := time.Now()
		err := h.chConn.QueryRow(countCtx, countSQL, args...).Scan(&total)
		h.recordCHQuery("list_count", "ebpf_events", start, err)
		if err != nil {
			h.logger.Error("ClickHouse 查询 EDR 事件总数失败", zap.Error(err))
			return err
		}
		return nil
	})

	g.Go(func() error {
		start := time.Now()
		rows, err := h.chConn.Query(dataCtx, dataSQL, args...)
		if err != nil {
			h.recordCHQuery("list_data", "ebpf_events", start, err)
			h.logger.Error("ClickHouse 查询 EDR 事件列表失败", zap.Error(err))
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ev chEDREvent
			if scanErr := rows.Scan(
				&ev.Timestamp, &ev.HostID, &ev.Hostname, &ev.EventType, &ev.DataType,
				&ev.PID, &ev.PPID, &ev.Exe, &ev.Cmdline, &ev.ParentExe,
				&ev.FilePath, &ev.RemoteAddr, &ev.RemotePort, &ev.LocalAddr, &ev.LocalPort,
				&ev.Protocol, &ev.UID, &ev.GID, &ev.ReturnCode,
			); scanErr != nil {
				h.logger.Warn("ClickHouse 单行扫描失败,跳过", zap.Error(scanErr))
				continue
			}
			events = append(events, ev)
		}
		// rows.Next() 在 ctx 超时 / CH 错误时静默返回 false,必须用 rows.Err() 判定真实结果
		if err := rows.Err(); err != nil {
			h.recordCHQuery("list_data", "ebpf_events", start, err)
			h.logger.Error("ClickHouse rows 迭代失败", zap.Error(err))
			return err
		}
		h.recordCHQuery("list_data", "ebpf_events", start, nil)
		return nil
	})

	if err := g.Wait(); err != nil {
		InternalError(c, "查询失败:数据量过大或时间窗口过宽,请缩窄过滤条件")
		return
	}

	SuccessPaginated(c, int64(total), events)
}

// EDREventStats EDR 事件统计
type EDREventStats struct {
	Total uint64 `json:"total"`
	// 按事件类型统计
	ProcessExec    uint64 `json:"process_exec"`
	FileOpen       uint64 `json:"file_open"`
	NetworkConnect uint64 `json:"network_connect"`
	// 按 DataType 统计
	ByDataType map[int32]uint64 `json:"by_data_type"`
	// Top 10 主机
	TopHosts []EDRHostEventCount `json:"top_hosts"`
	// Top 10 可执行文件
	TopExes []EDRExeCount `json:"top_exes"`
	// 趋势（按小时）
	Trend []EDREventTrendPoint `json:"trend"`
}

// EDRHostEventCount 主机事件数
type EDRHostEventCount struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Count    uint64 `json:"count"`
}

// EDRExeCount 可执行文件事件数
type EDRExeCount struct {
	Exe   string `json:"exe"`
	Count uint64 `json:"count"`
}

// EDREventTrendPoint 趋势数据点
type EDREventTrendPoint struct {
	Time  string `json:"time"`
	Count uint64 `json:"count"`
}

// GetEDREventStats 获取 EDR 事件统计
// GET /api/v1/edr/events/stats
//
// 5 个 CH 聚合查询并发执行(原串行 ~3s),总延迟 ≈ max(各 query) ≈ stats_top_hosts (~1.9s)。
// 后续可加 Redis cache 60s TTL,首次命中后 <10ms;但 handler 不含 redis client,
// 暂用并发达到 P0 目标,cache 留下一轮。
func (h *EDREventsHandler) GetEDREventStats(c *gin.Context) {
	if h.chConn == nil {
		Success(c, EDREventStats{
			ByDataType: map[int32]uint64{},
			TopHosts:   []EDRHostEventCount{},
			TopExes:    []EDRExeCount{},
			Trend:      []EDREventTrendPoint{},
		})
		return
	}

	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 720 {
		hours = 24
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), edrQueryCtxTimeout)
	defer cancel()
	chCtx := chQueryCtx(ctx)

	stats := EDREventStats{
		ByDataType: make(map[int32]uint64),
		TopHosts:   []EDRHostEventCount{},
		TopExes:    []EDRExeCount{},
		Trend:      []EDREventTrendPoint{},
	}

	g, _ := errgroup.WithContext(ctx)

	// 1. 总数 + 按事件类型统计(必返字段,失败时整体 500)
	g.Go(func() error {
		start := time.Now()
		row := h.chConn.QueryRow(chCtx, `
			SELECT
				count()                                    AS total,
				countIf(event_type = 'process_exec')       AS process_exec,
				countIf(event_type = 'file_open')          AS file_open,
				countIf(event_type = 'tcp_connect' OR event_type = 'udp_send') AS network_connect
			FROM ebpf_events
			WHERE timestamp >= subtractHours(now(), ?)`, hours)
		err := row.Scan(&stats.Total, &stats.ProcessExec, &stats.FileOpen, &stats.NetworkConnect)
		h.recordCHQuery("stats_total", "ebpf_events", start, err)
		if err != nil {
			h.logger.Error("ClickHouse EDR 统计 stats_total 失败", zap.Error(err))
			return err
		}
		return nil
	})

	// 2. 按 DataType 统计(非关键,失败仅记 metric,返回空 map)
	g.Go(func() error {
		start := time.Now()
		rows, err := h.chConn.Query(chCtx, `
			SELECT data_type, count() AS cnt
			FROM ebpf_events
			WHERE timestamp >= subtractHours(now(), ?)
			GROUP BY data_type`, hours)
		if err == nil {
			tmp := make(map[int32]uint64)
			for rows.Next() {
				var dt int32
				var cnt uint64
				if scanErr := rows.Scan(&dt, &cnt); scanErr == nil {
					tmp[dt] = cnt
				}
			}
			err = rows.Err()
			rows.Close()
			if err == nil {
				stats.ByDataType = tmp
			}
		}
		h.recordCHQuery("stats_by_data_type", "ebpf_events", start, err)
		return nil // 非关键,不抛错
	})

	// 3. Top 10 主机(非关键)
	g.Go(func() error {
		start := time.Now()
		rows, err := h.chConn.Query(chCtx, `
			SELECT host_id, hostname, count() AS cnt
			FROM ebpf_events
			WHERE timestamp >= subtractHours(now(), ?)
			GROUP BY host_id, hostname
			ORDER BY cnt DESC
			LIMIT 10`, hours)
		if err == nil {
			tmp := make([]EDRHostEventCount, 0, 10)
			for rows.Next() {
				var hc EDRHostEventCount
				if scanErr := rows.Scan(&hc.HostID, &hc.Hostname, &hc.Count); scanErr == nil {
					tmp = append(tmp, hc)
				}
			}
			err = rows.Err()
			rows.Close()
			if err == nil && len(tmp) > 0 {
				stats.TopHosts = tmp
			}
		}
		h.recordCHQuery("stats_top_hosts", "ebpf_events", start, err)
		return nil
	})

	// 4. Top 10 可执行文件(非关键)
	g.Go(func() error {
		start := time.Now()
		rows, err := h.chConn.Query(chCtx, `
			SELECT exe, count() AS cnt
			FROM ebpf_events
			WHERE timestamp >= subtractHours(now(), ?) AND exe != ''
			GROUP BY exe
			ORDER BY cnt DESC
			LIMIT 10`, hours)
		if err == nil {
			tmp := make([]EDRExeCount, 0, 10)
			for rows.Next() {
				var ec EDRExeCount
				if scanErr := rows.Scan(&ec.Exe, &ec.Count); scanErr == nil {
					tmp = append(tmp, ec)
				}
			}
			err = rows.Err()
			rows.Close()
			if err == nil && len(tmp) > 0 {
				stats.TopExes = tmp
			}
		}
		h.recordCHQuery("stats_top_exes", "ebpf_events", start, err)
		return nil
	})

	// 5. 趋势(非关键)
	g.Go(func() error {
		start := time.Now()
		rows, err := h.chConn.Query(chCtx, `
			SELECT toString(toStartOfHour(timestamp)) AS hour, count() AS cnt
			FROM ebpf_events
			WHERE timestamp >= subtractHours(now(), ?)
			GROUP BY hour
			ORDER BY hour ASC`, hours)
		if err == nil {
			tmp := make([]EDREventTrendPoint, 0, hours)
			for rows.Next() {
				var tp EDREventTrendPoint
				if scanErr := rows.Scan(&tp.Time, &tp.Count); scanErr == nil {
					tmp = append(tmp, tp)
				}
			}
			err = rows.Err()
			rows.Close()
			if err == nil && len(tmp) > 0 {
				stats.Trend = tmp
			}
		}
		h.recordCHQuery("stats_trend", "ebpf_events", start, err)
		return nil
	})

	if err := g.Wait(); err != nil {
		InternalError(c, "查询失败")
		return
	}

	Success(c, stats)
}
