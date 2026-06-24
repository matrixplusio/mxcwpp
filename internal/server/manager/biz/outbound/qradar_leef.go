package outbound

// IBM QRadar LEEF (Log Event Extended Format) connector (P2-18).
//
// LEEF 2.0 格式: https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components
//
// 格式:
//   LEEF:2.0|Vendor|Product|Version|EventID|<key1>=<val1>\t<key2>=<val2>...
//   LEEF:2.0|mxcwpp|mxcwpp|2.0|MXCWPP-ALERT|cat=intrusion\tseverity=high\t...
//
// 传输: 通过 syslog UDP/TCP 推 QRadar Event Collector.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// QRadarLEEFConnector 通过 syslog 推 LEEF 格式到 QRadar.
type QRadarLEEFConnector struct {
	endpoint string
	network  string // udp / tcp
	logger   *zap.Logger
	mu       sync.Mutex
	conn     net.Conn
}

// NewQRadarLEEFConnector 构造.
func NewQRadarLEEFConnector(network, endpoint string, logger *zap.Logger) *QRadarLEEFConnector {
	if logger == nil {
		logger = zap.NewNop()
	}
	if network == "" {
		network = "udp"
	}
	return &QRadarLEEFConnector{
		endpoint: endpoint,
		network:  network,
		logger:   logger,
	}
}

// Name 名字.
func (c *QRadarLEEFConnector) Name() string { return "qradar_leef" }

// Send 把 Event 转 LEEF 2.0 格式 + 通过 syslog 发送.
func (c *QRadarLEEFConnector) Send(ctx context.Context, ev *Event) error {
	// LEEF 2.0 header
	header := fmt.Sprintf("LEEF:2.0|mxcwpp|mxcwpp|2.0|%s",
		escapeLEEFHeader(ev.RuleID))

	// LEEF body (tab-separated key=value)
	kv := []string{
		"cat=" + escapeLEEFValue(ev.Category),
		"sev=" + mapLEEFSeverity(ev.Severity),
		"devTime=" + ev.Timestamp.UTC().Format(time.RFC3339),
		"src=" + escapeLEEFValue(ev.HostName),
		"alertId=" + escapeLEEFValue(ev.ID),
		"hostId=" + escapeLEEFValue(ev.HostID),
		"tenant=" + escapeLEEFValue(ev.TenantID),
		"mitre=" + escapeLEEFValue(ev.MitreID),
		"msg=" + escapeLEEFValue(ev.Title),
		"description=" + escapeLEEFValue(ev.Description),
		"source=" + escapeLEEFValue(ev.Source),
	}
	body := strings.Join(kv, "\t")

	// Wrap syslog RFC 3164 prefix (QRadar 默认接收 syslog)
	syslogPrefix := fmt.Sprintf("<134>%s mxcwpp ",
		time.Now().Format("Jan _2 15:04:05"))

	msg := syslogPrefix + header + "|" + body + "\n"

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, c.network, c.endpoint)
		if err != nil {
			return fmt.Errorf("qradar dial: %w", err)
		}
		c.conn = conn
	}
	if _, err := c.conn.Write([]byte(msg)); err != nil {
		_ = c.conn.Close()
		c.conn = nil
		return fmt.Errorf("qradar write: %w", err)
	}
	return nil
}

// Close 关闭 conn.
func (c *QRadarLEEFConnector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// mapLEEFSeverity mxcwpp severity → LEEF 1-10.
//
// LEEF: 1 (info) → 10 (critical).
func mapLEEFSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "10"
	case "high":
		return "8"
	case "medium":
		return "5"
	case "low":
		return "3"
	case "info":
		return "1"
	}
	return "5"
}

// escapeLEEFHeader 转义 LEEF header 中的 | (pipe).
func escapeLEEFHeader(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// escapeLEEFValue 转义 LEEF body 中的 tab 和 \n.
func escapeLEEFValue(s string) string {
	s = strings.ReplaceAll(s, "\t", "\\t")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}
