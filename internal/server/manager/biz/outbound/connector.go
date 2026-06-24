// Package outbound 实现告警/事件外发到 SIEM/SOC 系统 (P2-3)。
//
// ref/01 P1-3: 5 种外发连接器 (Syslog/Splunk HEC/Elastic Bulk/阿里 SLS/QRadar LEEF)
// 本 PR 实现核心 3 种: Syslog (RFC 5424) + Webhook (通用 JSON POST) + File (本地落盘)
// Splunk HEC + Elastic Bulk + SLS + QRadar 后续 PR (实际都是 Webhook 派生)
package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Event 是外发的通用告警 event 结构。
//
// Connector 各自把这个 struct 映射到目标格式。
type Event struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	HostID      string         `json:"host_id"`
	HostName    string         `json:"host_name,omitempty"`
	Severity    string         `json:"severity"`
	Category    string         `json:"category"`
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	MitreID     string         `json:"mitre_id,omitempty"`
	Source      string         `json:"source"` // engine.alert / fim.event / baseline.fail / ...
	Timestamp   time.Time      `json:"timestamp"`
	Fields      map[string]any `json:"fields,omitempty"`
}

// Connector 接口: 每种外发实现一个。
type Connector interface {
	Name() string
	Send(ctx context.Context, ev *Event) error
	Close() error
}

// ============================ Syslog (RFC 5424) ============================

// SyslogConnector 通过 RFC 5424 UDP/TCP 发送 syslog。
//
// 实际客户场景:
//   - 企业 SIEM (IBM QRadar / ArcSight / Splunk Syslog 入口)
//   - 国产 SOC (奇安信 NGSOC / 安恒)
//   - 等保审计要求 syslog 集中
type SyslogConnector struct {
	endpoint string // host:port
	network  string // udp / tcp
	facility int    // RFC 5424 facility (default 10 security/auth)
	hostname string
	appname  string
	logger   *zap.Logger

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslogConnector 构造。endpoint 例 "siem.corp.local:514"。
func NewSyslogConnector(network, endpoint, hostname, appname string, logger *zap.Logger) *SyslogConnector {
	if logger == nil {
		logger = zap.NewNop()
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if appname == "" {
		appname = "mxcwpp"
	}
	if network == "" {
		network = "udp"
	}
	return &SyslogConnector{
		endpoint: endpoint,
		network:  network,
		facility: 10,
		hostname: hostname,
		appname:  appname,
		logger:   logger,
	}
}

// Name 名字。
func (c *SyslogConnector) Name() string { return "syslog" }

// Send 序列化 RFC 5424 + 写网络。
//
// 格式:
//
//	<PRI>1 timestamp hostname appname procid msgid [SD-IDs] JSON
//	<134>1 2026-06-07T12:00:00.000Z host01 mxcwpp - alrt-xyz - {"severity":"high",...}
func (c *SyslogConnector) Send(ctx context.Context, ev *Event) error {
	severity := mapSyslogSeverity(ev.Severity)
	pri := c.facility*8 + severity
	ts := ev.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
	body, _ := json.Marshal(ev)
	msg := fmt.Sprintf("<%d>1 %s %s %s - %s - %s\n",
		pri, ts, c.hostname, c.appname, ev.ID, body)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(ctx); err != nil {
		return err
	}
	if _, err := c.conn.Write([]byte(msg)); err != nil {
		_ = c.conn.Close()
		c.conn = nil
		return fmt.Errorf("syslog write: %w", err)
	}
	return nil
}

func (c *SyslogConnector) ensureConn(ctx context.Context) error {
	if c.conn != nil {
		return nil
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, c.network, c.endpoint)
	if err != nil {
		return fmt.Errorf("syslog dial: %w", err)
	}
	c.conn = conn
	return nil
}

// Close 关闭网络连接。
func (c *SyslogConnector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	return nil
}

// mapSyslogSeverity mxcwpp severity → RFC 5424 0-7 (0=emerg).
func mapSyslogSeverity(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 2 // crit
	case "high":
		return 3 // err
	case "medium":
		return 4 // warning
	case "low":
		return 5 // notice
	case "info":
		return 6
	}
	return 6
}

// ============================ Webhook (通用 JSON POST) ============================

// WebhookConnector 把 Event JSON POST 到任意 URL。
//
// 兼容场景:
//   - 自研 SOC 接收 API
//   - 钉钉/飞书/Slack incoming webhook (后续 PR 加 message format adapter)
//   - Splunk HEC (Header: Authorization: Splunk <token>)
//   - Elastic Bulk (后续 PR 改写 bulk NDJSON 格式)
type WebhookConnector struct {
	url     string
	method  string
	headers map[string]string
	client  *http.Client
	logger  *zap.Logger
}

// NewWebhookConnector 构造。
func NewWebhookConnector(url, method string, headers map[string]string, logger *zap.Logger) *WebhookConnector {
	if logger == nil {
		logger = zap.NewNop()
	}
	if method == "" {
		method = "POST"
	}
	return &WebhookConnector{
		url:     url,
		method:  method,
		headers: headers,
		client:  &http.Client{Timeout: 10 * time.Second},
		logger:  logger,
	}
}

// Name 名字。
func (c *WebhookConnector) Name() string { return "webhook" }

// Send POST JSON 到 URL。
func (c *WebhookConnector) Send(ctx context.Context, ev *Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, c.method, c.url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// Close 释放 http client。
func (c *WebhookConnector) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

// ============================ File (本地 JSON 行) ============================

// FileConnector 把 Event 写本地文件 (一行一条 JSON)。
//
// 用途: 单机演示 / 客户私有化交付 (logrotate + filebeat 转出)。
type FileConnector struct {
	path   string
	logger *zap.Logger

	mu sync.Mutex
	f  *os.File
}

// NewFileConnector 构造。
func NewFileConnector(path string, logger *zap.Logger) (*FileConnector, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &FileConnector{path: path, logger: logger, f: f}, nil
}

// Name 名字。
func (c *FileConnector) Name() string { return "file" }

// Send 追加 JSON 行。
func (c *FileConnector) Send(_ context.Context, ev *Event) error {
	body, _ := json.Marshal(ev)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.f.Write(append(body, '\n')); err != nil {
		return err
	}
	return nil
}

// Close 关闭文件句柄。
func (c *FileConnector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f != nil {
		err := c.f.Close()
		c.f = nil
		return err
	}
	return nil
}

// ============================ Dispatcher (多 connector 并发) ============================

// Dispatcher 把同一 Event 派发给多个 Connector (broadcast)。
type Dispatcher struct {
	connectors []Connector
	logger     *zap.Logger
}

// NewDispatcher 构造。
func NewDispatcher(logger *zap.Logger, connectors ...Connector) *Dispatcher {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Dispatcher{connectors: connectors, logger: logger}
}

// Send 并发派发, 任一失败不影响其他。
func (d *Dispatcher) Send(ctx context.Context, ev *Event) error {
	if len(d.connectors) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for _, c := range d.connectors {
		wg.Add(1)
		go func(c Connector) {
			defer wg.Done()
			if err := c.Send(ctx, ev); err != nil {
				d.logger.Warn("outbound send failed",
					zap.String("connector", c.Name()),
					zap.String("event_id", ev.ID),
					zap.Error(err))
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	if firstErr != nil {
		return fmt.Errorf("at least one connector failed: %w", firstErr)
	}
	return nil
}

// Close 关闭所有 connector。
func (d *Dispatcher) Close() error {
	var errs []error
	for _, c := range d.connectors {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
