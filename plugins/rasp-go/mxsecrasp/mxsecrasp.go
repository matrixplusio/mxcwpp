// Package mxsecrasp 提供 Go 应用程序的 RASP 观察 SDK (P4-14).
//
// 使用方式 (业务代码侧):
//
//	import "github.com/imkerbos/mxsec-platform/plugins/rasp-go/mxsecrasp"
//
//	func main() {
//	    mxsecrasp.Install(mxsecrasp.Config{
//	        UDSPath: "/var/run/mxsec/rasp-go.sock",
//	        TenantID: "t-default",
//	    })
//	    defer mxsecrasp.Shutdown()
//	    // ... 业务代码 ...
//	}
//
// 然后在敏感调用点上报:
//
//	cmd := exec.Command("/bin/sh", "-c", input)
//	mxsecrasp.ObserveCmdExec(cmd.Path, cmd.Args)
//	cmd.Run()
//
// 严格 read-only RASP: 仅观察 + 上报到 UDS, 不阻塞调用.
//
// Go 没有运行时 monkey patch 能力, 所以用 SDK 风格 (业务显式调) 而不是 PHP/Python 的 audit hook.
// 后续可结合 ebpf/uretprobe 在 syscall 层无侵入观察.
package mxsecrasp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Config Reporter 配置.
type Config struct {
	UDSPath            string
	TenantID           string
	QueueCapacity      int
	MaxEventsPerSecond int
	ReconnectInterval  time.Duration
}

// DefaultConfig 默认值.
func DefaultConfig() Config {
	return Config{
		UDSPath:            "/var/run/mxsec/rasp-go.sock",
		TenantID:           "t-default",
		QueueCapacity:      10000,
		MaxEventsPerSecond: 5000,
		ReconnectInterval:  3 * time.Second,
	}
}

// Event 一条观察事件.
type Event struct {
	Kind        string   `json:"kind"`
	ClassName   string   `json:"class_name"`
	MethodName  string   `json:"method_name"`
	Arguments   []string `json:"arguments,omitempty"`
	StackTrace  string   `json:"stack_trace,omitempty"`
	HTTPMethod  string   `json:"http_method,omitempty"`
	HTTPURL     string   `json:"http_url,omitempty"`
	HTTPClient  string   `json:"http_client,omitempty"`
	PID         int      `json:"pid"`
	TenantID    string   `json:"tenant_id"`
	TimestampMS int64    `json:"timestamp"`
	Mode        string   `json:"mode"`
	Language    string   `json:"language"`
}

var (
	gMu        sync.Mutex
	gReporter  *reporter
	gInstalled atomic.Bool
)

// Install 启动 reporter (重复调用安全, 只生效第一次).
func Install(cfg Config) {
	if !gInstalled.CompareAndSwap(false, true) {
		return
	}
	if cfg.UDSPath == "" {
		cfg.UDSPath = DefaultConfig().UDSPath
	}
	if cfg.QueueCapacity == 0 {
		cfg.QueueCapacity = DefaultConfig().QueueCapacity
	}
	if cfg.MaxEventsPerSecond == 0 {
		cfg.MaxEventsPerSecond = DefaultConfig().MaxEventsPerSecond
	}
	if cfg.ReconnectInterval == 0 {
		cfg.ReconnectInterval = DefaultConfig().ReconnectInterval
	}
	r := newReporter(cfg)
	gReporter = r
	go r.run()
}

// Shutdown 关闭 reporter (一般 defer 在 main).
func Shutdown() {
	gMu.Lock()
	defer gMu.Unlock()
	if gReporter != nil {
		gReporter.stop()
		gReporter = nil
	}
	gInstalled.Store(false)
}

// ObserveCmdExec 业务调 exec.Command 之前调用.
func ObserveCmdExec(path string, args []string) {
	r := gReporter
	if r == nil {
		return
	}
	argStrs := make([]string, 0, len(args))
	for _, a := range args {
		argStrs = append(argStrs, truncate(a, 256))
	}
	r.enqueue(makeEvent("cmd_exec", "os/exec", "Command", argStrs))
}

// ObserveSQLQuery 业务调 db.Query 之前调用.
func ObserveSQLQuery(driver string, query string) {
	r := gReporter
	if r == nil {
		return
	}
	r.enqueue(makeEvent("sql_query", "database/sql", driver, []string{truncate(query, 1024)}))
}

// ObserveHTTPOut 业务调 http.Client.Do 之前调用.
func ObserveHTTPOut(method string, url string) {
	r := gReporter
	if r == nil {
		return
	}
	ev := makeEvent("http_out", "net/http", "Client.Do", nil)
	ev.HTTPMethod = method
	ev.HTTPURL = truncate(url, 512)
	r.enqueue(ev)
}

// ObserveFileWrite 业务写关键文件路径之前调用.
func ObserveFileWrite(path string) {
	r := gReporter
	if r == nil {
		return
	}
	r.enqueue(makeEvent("file_write", "os", "WriteFile", []string{truncate(path, 256)}))
}

// ObservePluginLoad 业务 plugin.Open 之前调用.
func ObservePluginLoad(soPath string) {
	r := gReporter
	if r == nil {
		return
	}
	r.enqueue(makeEvent("plugin_load", "plugin", "Open", []string{truncate(soPath, 256)}))
}

func makeEvent(kind, className, methodName string, args []string) Event {
	tenantID := "t-default"
	if gReporter != nil {
		tenantID = gReporter.cfg.TenantID
	}
	return Event{
		Kind:        kind,
		ClassName:   className,
		MethodName:  methodName,
		Arguments:   args,
		StackTrace:  captureStack(3),
		PID:         os.Getpid(),
		TenantID:    tenantID,
		TimestampMS: time.Now().UnixMilli(),
		Mode:        "observe",
		Language:    "go",
	}
}

func captureStack(skip int) string {
	pcs := make([]uintptr, 30)
	n := runtime.Callers(skip, pcs)
	if n == 0 {
		return ""
	}
	frames := runtime.CallersFrames(pcs[:n])
	var sb []byte
	for {
		f, more := frames.Next()
		sb = append(sb, f.Function...)
		sb = append(sb, '\n')
		if !more {
			break
		}
	}
	return string(sb)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// reporter UDS 帧发送器.
type reporter struct {
	cfg    Config
	queue  chan Event
	stopCh chan struct{}
	rps    atomic.Int64
	rpsAt  atomic.Int64
	conn   net.Conn
	connMu sync.Mutex
}

func newReporter(cfg Config) *reporter {
	return &reporter{
		cfg:    cfg,
		queue:  make(chan Event, cfg.QueueCapacity),
		stopCh: make(chan struct{}),
	}
}

func (r *reporter) enqueue(ev Event) {
	now := time.Now().UnixMilli()
	if now-r.rpsAt.Load() > 1000 {
		r.rps.Store(0)
		r.rpsAt.Store(now)
	}
	if r.rps.Add(1) > int64(r.cfg.MaxEventsPerSecond) {
		return
	}
	select {
	case r.queue <- ev:
	default:
		// drop oldest
		select {
		case <-r.queue:
		default:
		}
		select {
		case r.queue <- ev:
		default:
		}
	}
}

// run P0-3: batch flush 模式 — 攒事件到 64KB / 10ms 阈值再一次 syscall, 减 90% UDS write 调用.
func (r *reporter) run() {
	r.reconnect(context.Background())
	const (
		flushInterval = 10 * time.Millisecond
		flushBytes    = 64 * 1024
		flushCount    = 100
	)
	buf := make([]byte, 0, flushBytes*2)
	pending := 0
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	flush := func() {
		if pending == 0 {
			return
		}
		r.flushBuf(buf)
		buf = buf[:0]
		pending = 0
	}

	for {
		select {
		case <-r.stopCh:
			flush()
			r.closeConn()
			return
		case ev := <-r.queue:
			payload, err := json.Marshal(ev)
			if err == nil {
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
				buf = append(buf, header[:]...)
				buf = append(buf, payload...)
				pending++
				if len(buf) >= flushBytes || pending >= flushCount {
					flush()
				}
			}
		case <-ticker.C:
			flush()
		}
	}
}

// flushBuf 一次 syscall 写所有累积 frame.
func (r *reporter) flushBuf(buf []byte) {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.conn == nil {
		// 重连时丢这一批 (调用方应预期 reconnect 期间 drop)
		return
	}
	if _, err := r.conn.Write(buf); err != nil {
		_ = r.conn.Close()
		r.conn = nil
		// 触发外层重连
	}
}

func (r *reporter) stop() {
	close(r.stopCh)
}

func (r *reporter) reconnect(ctx context.Context) {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}
		c, err := net.DialTimeout("unix", r.cfg.UDSPath, 2*time.Second)
		if err == nil {
			r.conn = c
			return
		}
		time.Sleep(r.cfg.ReconnectInterval)
	}
}

func (r *reporter) closeConn() {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
}
