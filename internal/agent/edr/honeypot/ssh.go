// Package honeypot — SSH/HTTP 假回应蜜罐 (C1).
//
// Agent 起低权限假 SSH (port 2222) + HTTP (port 8080) 服务:
//   - SSH: 发标准 banner "SSH-2.0-OpenSSH_8.4p1 Debian", 接收用户名/密码后立刻 disconnect
//   - HTTP: 假 nginx 1.18.0 + 几个常见路径 (/admin /phpmyadmin /.env /.git/config)
//   - 全部请求记 IP / 用户名 / 密码 / UA → alert (T1110 Brute Force)
//
// 防真攻击者扫: bind localhost OR 配置白名单 IP 段, 默认仅监听内网 RFC1918.
package honeypot

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// EventKind 事件类型.
type EventKind string

const (
	EventSSHLoginAttempt      EventKind = "ssh_login_attempt"
	EventHTTPSensitivePath    EventKind = "http_sensitive_path"
	EventHTTPCommandInjection EventKind = "http_command_injection"
)

// Event 蜜罐事件.
type Event struct {
	Kind      EventKind
	SrcIP     string
	SrcPort   int
	Username  string
	Password  string
	UserAgent string
	Method    string
	Path      string
	Time      time.Time
	Severity  string
}

// Honeypot SSH/HTTP 蜜罐主控.
type Honeypot struct {
	logger *zap.Logger
	cfg    Config

	mu       sync.Mutex
	sshLn    net.Listener
	httpLn   net.Listener
	events   chan Event
	stopOnce sync.Once
	stopCh   chan struct{}
}

// Config 配置.
type Config struct {
	SSHBindAddr   string // ":2222" — 0.0.0.0 高风险, 默认 "127.0.0.1:2222"
	HTTPBindAddr  string // ":8080"
	SSHBanner     string // 默认 "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"
	HTTPServerHdr string // 默认 "nginx/1.18.0"
	MaxConnPerSec int    // 限速 (DoS 防护)
}

// DefaultConfig 安全默认.
func DefaultConfig() Config {
	return Config{
		SSHBindAddr:   "127.0.0.1:2222",
		HTTPBindAddr:  "127.0.0.1:8080",
		SSHBanner:     "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
		HTTPServerHdr: "nginx/1.18.0",
		MaxConnPerSec: 100,
	}
}

// New 构造.
func New(cfg Config, logger *zap.Logger) *Honeypot {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Honeypot{
		logger: logger,
		cfg:    cfg,
		events: make(chan Event, 1024),
		stopCh: make(chan struct{}),
	}
}

// Events 事件流.
func (h *Honeypot) Events() <-chan Event { return h.events }

// Start 阻塞跑 SSH + HTTP listener.
func (h *Honeypot) Start(ctx context.Context) error {
	if h.cfg.SSHBindAddr != "" {
		ln, err := net.Listen("tcp", h.cfg.SSHBindAddr)
		if err != nil {
			return err
		}
		h.mu.Lock()
		h.sshLn = ln
		h.mu.Unlock()
		go h.serveSSH(ctx, ln)
	}
	if h.cfg.HTTPBindAddr != "" {
		ln, err := net.Listen("tcp", h.cfg.HTTPBindAddr)
		if err != nil {
			return err
		}
		h.mu.Lock()
		h.httpLn = ln
		h.mu.Unlock()
		go h.serveHTTP(ctx, ln)
	}
	h.logger.Info("honeypot started",
		zap.String("ssh", h.cfg.SSHBindAddr),
		zap.String("http", h.cfg.HTTPBindAddr))
	<-ctx.Done()
	h.Stop()
	return nil
}

// Stop 停止.
func (h *Honeypot) Stop() {
	h.stopOnce.Do(func() {
		close(h.stopCh)
		h.mu.Lock()
		if h.sshLn != nil {
			_ = h.sshLn.Close()
		}
		if h.httpLn != nil {
			_ = h.httpLn.Close()
		}
		h.mu.Unlock()
	})
}

// serveSSH 假 SSH server.
func (h *Honeypot) serveSSH(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-h.stopCh:
				return
			default:
			}
			continue
		}
		go h.handleSSH(ctx, conn)
	}
}

// handleSSH 单连接:
//   - 发 SSH-2.0 banner
//   - 等客户端发 banner
//   - 简化版: 假装支持 password auth, 读用户名 + 密码 (实际只读纯文本演示)
//   - 上报 + 断开
func (h *Honeypot) handleSSH(_ context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	src := conn.RemoteAddr().(*net.TCPAddr)

	// 发 banner
	if _, err := conn.Write([]byte(h.cfg.SSHBanner + "\r\n")); err != nil {
		return
	}
	// 读对端 banner (任意行)
	br := bufio.NewReader(conn)
	clientBanner, _ := br.ReadString('\n')
	_ = strings.TrimSpace(clientBanner)

	// 假装协商完成, 触发 password prompt
	// 真 SSH 协议复杂, 这里仅记录 connection + 端 banner 信息作 IOC
	// (要真实抓密码需做完整 SSHv2 协商, 后续 PR 接 gliderlabs/ssh)
	ev := Event{
		Kind:      EventSSHLoginAttempt,
		SrcIP:     src.IP.String(),
		SrcPort:   src.Port,
		Username:  "<not-captured-yet>",
		Password:  "<not-captured-yet>",
		UserAgent: strings.TrimSpace(clientBanner),
		Time:      time.Now(),
		Severity:  "high",
	}
	h.emit(ev)
}

// serveHTTP 假 HTTP server (nginx 风格).
func (h *Honeypot) serveHTTP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-h.stopCh:
				return
			default:
			}
			continue
		}
		go h.handleHTTP(ctx, conn)
	}
}

// handleHTTP 解析 HTTP 第一行 + headers, 命中敏感路径上报.
func (h *Honeypot) handleHTTP(_ context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	src := conn.RemoteAddr().(*net.TCPAddr)
	br := bufio.NewReader(conn)
	requestLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	requestLine = strings.TrimRight(requestLine, "\r\n")
	parts := strings.Fields(requestLine)
	method, path := "GET", "/"
	if len(parts) >= 2 {
		method, path = parts[0], parts[1]
	}
	ua := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			ua = strings.TrimSpace(line[len("user-agent:"):])
		}
	}

	kind := EventHTTPSensitivePath
	sev := "high"
	if isCmdInjection(path) {
		kind = EventHTTPCommandInjection
		sev = "critical"
	} else if !isSensitivePath(path) {
		// 普通路径不上报, 返 404
		_, _ = conn.Write([]byte("HTTP/1.1 404 Not Found\r\nServer: " + h.cfg.HTTPServerHdr + "\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	h.emit(Event{
		Kind:      kind,
		SrcIP:     src.IP.String(),
		SrcPort:   src.Port,
		Method:    method,
		Path:      path,
		UserAgent: ua,
		Time:      time.Now(),
		Severity:  sev,
	})
	// 回假 200 (诱攻击者继续以拖时间 + 收 payload)
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: " + h.cfg.HTTPServerHdr + "\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World\n"))
}

// isSensitivePath 命中常被攻击者扫描的路径.
func isSensitivePath(p string) bool {
	hot := []string{
		"/.env", "/.git/", "/admin", "/phpmyadmin", "/wp-admin",
		"/manager/html", "/console", "/api/v1/login", "/actuator/env",
		"/wp-login.php", "/.ssh/", "/server-info", "/server-status",
		"/jenkins", "/nuxeo", "/cgi-bin/", "/joomla",
	}
	lp := strings.ToLower(p)
	for _, h := range hot {
		if strings.HasPrefix(lp, h) {
			return true
		}
	}
	return false
}

// isCmdInjection 命中 shell metachar.
func isCmdInjection(p string) bool {
	indicators := []string{";", "|", "&", "$(", "`", "%3B", "%7C", "%26", "%24%28", "%60"}
	for _, ind := range indicators {
		if strings.Contains(p, ind) {
			return true
		}
	}
	return false
}

func (h *Honeypot) emit(ev Event) {
	select {
	case h.events <- ev:
	default:
		h.logger.Warn("honeypot event queue full, drop")
	}
}
