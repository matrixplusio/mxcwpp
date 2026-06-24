// Package siem provides SIEM integration via Syslog CEF (Common Event Format).
// Security events (EDR alerts, IOC hits, rule matches) are forwarded to
// external SIEM systems (Splunk, QRadar, ArcSight, ELK, etc.) in real-time.
//
// CEF Format: CEF:0|MxCwpp|EDR|1.0|<eventID>|<name>|<severity>|<extensions>
package siem

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Severity maps internal severity strings to CEF severity levels (0-10).
var severityMap = map[string]int{
	"info":     1,
	"low":      3,
	"medium":   5,
	"high":     7,
	"critical": 10,
}

// Config holds SIEM output configuration.
type Config struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Protocol string `json:"protocol" yaml:"protocol"` // "tcp" or "udp"
	Address  string `json:"address" yaml:"address"`   // "siem.example.com:514"
	Facility int    `json:"facility" yaml:"facility"` // syslog facility (default 1 = user-level)
}

// Forwarder sends security events to a SIEM system via Syslog CEF.
type Forwarder struct {
	logger *zap.Logger
	cfg    Config
	mu     sync.Mutex
	conn   net.Conn
	sent   uint64
	errors uint64
}

// NewForwarder creates a SIEM forwarder. Returns nil if not enabled.
func NewForwarder(logger *zap.Logger, cfg Config) *Forwarder {
	if !cfg.Enabled || cfg.Address == "" {
		return nil
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "udp"
	}
	if cfg.Facility == 0 {
		cfg.Facility = 1 // user-level
	}

	f := &Forwarder{
		logger: logger,
		cfg:    cfg,
	}

	if err := f.connect(); err != nil {
		logger.Warn("SIEM connection failed, will retry on next event",
			zap.String("address", cfg.Address),
			zap.Error(err))
	} else {
		logger.Info("SIEM forwarder connected",
			zap.String("address", cfg.Address),
			zap.String("protocol", cfg.Protocol))
	}

	return f
}

// SendAlert forwards a security alert to the SIEM.
func (f *Forwarder) SendAlert(alert AlertEvent) {
	cef := f.formatCEF(alert)
	syslog := f.formatSyslog(cef)

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.conn == nil {
		if err := f.connect(); err != nil {
			f.errors++
			return
		}
	}

	_ = f.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := f.conn.Write([]byte(syslog)); err != nil {
		f.errors++
		f.conn.Close()
		f.conn = nil
		return
	}
	f.sent++
}

// Stats returns sent and error counters.
func (f *Forwarder) Stats() (sent, errors uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent, f.errors
}

// Close closes the SIEM connection.
func (f *Forwarder) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		f.conn.Close()
		f.conn = nil
	}
}

// AlertEvent represents a security event to forward to SIEM.
type AlertEvent struct {
	EventID  string // e.g. "rule_match", "ioc_hit", "yara_match"
	Name     string // human-readable event name
	Severity string // "info", "low", "medium", "high", "critical"
	HostID   string
	Hostname string
	SourceIP string
	DestIP   string
	PID      string
	Exe      string
	Cmdline  string
	RuleID   string
	MITRE    string            // MITRE ATT&CK technique
	Extra    map[string]string // additional key=value pairs
}

func (f *Forwarder) formatCEF(a AlertEvent) string {
	sev := severityMap[a.Severity]
	if sev == 0 {
		sev = 5
	}

	// CEF extensions.
	var ext []string
	if a.HostID != "" {
		ext = append(ext, "dvchost="+cefEscape(a.HostID))
	}
	if a.Hostname != "" {
		ext = append(ext, "dhost="+cefEscape(a.Hostname))
	}
	if a.SourceIP != "" {
		ext = append(ext, "src="+a.SourceIP)
	}
	if a.DestIP != "" {
		ext = append(ext, "dst="+a.DestIP)
	}
	if a.PID != "" {
		ext = append(ext, "sproc="+a.PID)
	}
	if a.Exe != "" {
		ext = append(ext, "filePath="+cefEscape(a.Exe))
	}
	if a.Cmdline != "" {
		ext = append(ext, "msg="+cefEscape(a.Cmdline))
	}
	if a.RuleID != "" {
		ext = append(ext, "cs1="+cefEscape(a.RuleID))
		ext = append(ext, "cs1Label=RuleID")
	}
	if a.MITRE != "" {
		ext = append(ext, "cs2="+cefEscape(a.MITRE))
		ext = append(ext, "cs2Label=MITRE")
	}
	for k, v := range a.Extra {
		ext = append(ext, fmt.Sprintf("cs3=%s", cefEscape(k+"="+v)))
	}

	return fmt.Sprintf("CEF:0|MxCwpp|EDR|1.0|%s|%s|%d|%s",
		cefEscape(a.EventID),
		cefEscape(a.Name),
		sev,
		strings.Join(ext, " "))
}

func (f *Forwarder) formatSyslog(cef string) string {
	// RFC 3164 syslog format.
	pri := f.cfg.Facility*8 + 6 // facility + severity=informational
	timestamp := time.Now().Format("Jan 02 15:04:05")
	hostname, _ := os.Hostname()
	return fmt.Sprintf("<%d>%s %s mxcwpp-edr: %s\n", pri, timestamp, hostname, cef)
}

func (f *Forwarder) connect() error {
	conn, err := net.DialTimeout(f.cfg.Protocol, f.cfg.Address, 10*time.Second)
	if err != nil {
		return err
	}
	f.conn = conn
	return nil
}

// cefEscape escapes special characters in CEF values.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
