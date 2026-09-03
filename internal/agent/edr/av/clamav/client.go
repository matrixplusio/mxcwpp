// Package clamav — clamd UDS / TCP 客户端 (B8).
//
// 实现 clamd 协议命令:
//   - PING      → "PONG"
//   - VERSION   → "ClamAV 0.x.x/yyyy-mm-dd"
//   - SCAN <p>  → "/path: <virus>|OK"
//   - INSTREAM  → 4 byte BE chunk length + payload (终 0 长度)
//   - STATS     → threads/mem/queue
//
// 文档: https://manpages.debian.org/buster/clamav-daemon/clamd.8.en.html
package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Client clamd 客户端.
type Client struct {
	addr    string        // unix:///var/run/clamav/clamd.ctl 或 tcp://1.2.3.4:3310
	timeout time.Duration // 单次操作超时
}

// New 构造.
//
// addr 形式:
//   - "unix:///var/run/clamav/clamd.ctl"
//   - "/var/run/clamav/clamd.ctl" (省 scheme, 视为 UDS)
//   - "tcp://1.2.3.4:3310"
//   - "1.2.3.4:3310" (省 scheme, 视为 TCP)
func New(addr string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{addr: addr, timeout: timeout}
}

// dial 建连.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	network, target := c.parseAddr()
	d := net.Dialer{Timeout: c.timeout}
	return d.DialContext(ctx, network, target)
}

func (c *Client) parseAddr() (network, target string) {
	a := c.addr
	switch {
	case strings.HasPrefix(a, "unix://"):
		return "unix", strings.TrimPrefix(a, "unix://")
	case strings.HasPrefix(a, "tcp://"):
		return "tcp", strings.TrimPrefix(a, "tcp://")
	case strings.HasPrefix(a, "/"):
		return "unix", a
	default:
		return "tcp", a
	}
}

// Ping 测连通性.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.cmd(ctx, "zPING\x00")
	if err != nil {
		return err
	}
	resp = strings.TrimRight(resp, "\x00\n")
	if resp != "PONG" {
		return fmt.Errorf("clamd ping unexpected: %q", resp)
	}
	return nil
}

// Version 返 ClamAV 版本字符串.
func (c *Client) Version(ctx context.Context) (string, error) {
	return c.cmd(ctx, "zVERSION\x00")
}

// ScanFile 扫描指定文件 (clamd 需有读权限).
func (c *Client) ScanFile(ctx context.Context, path string) (*ScanResult, error) {
	resp, err := c.cmd(ctx, "zSCAN "+path+"\x00")
	if err != nil {
		return nil, err
	}
	return parseScanResp(resp)
}

// ScanStream INSTREAM 命令: 把内存中 data 发给 clamd 扫描.
//
// chunk size 默认 64KB. clamd 配置 StreamMaxLength 上限 (默认 25MB) 超会拒绝.
func (c *Client) ScanStream(ctx context.Context, r io.Reader) (*ScanResult, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, fmt.Errorf("write cmd: %w", err)
	}
	buf := make([]byte, 64*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, werr := conn.Write(hdr[:]); werr != nil {
				return nil, fmt.Errorf("write chunk hdr: %w", werr)
			}
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return nil, fmt.Errorf("write chunk body: %w", werr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read source: %w", err)
		}
	}
	// 0 长度结束帧
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("write eof: %w", err)
	}
	resp, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read resp: %w", err)
	}
	return parseScanResp(resp)
}

// Stats clamd 状态.
func (c *Client) Stats(ctx context.Context) (string, error) {
	return c.cmd(ctx, "zSTATS\x00")
}

// Reload 重载病毒库 (不停服务).
func (c *Client) Reload(ctx context.Context) error {
	resp, err := c.cmd(ctx, "zRELOAD\x00")
	if err != nil {
		return err
	}
	resp = strings.TrimRight(resp, "\x00\n")
	if resp != "RELOADING" {
		return fmt.Errorf("clamd reload unexpected: %q", resp)
	}
	return nil
}

func (c *Client) cmd(ctx context.Context, cmd string) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	resp, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read: %w", err)
	}
	return resp, nil
}

// ScanResult clamd 扫描结果.
type ScanResult struct {
	Path      string
	Clean     bool
	VirusName string
	Raw       string
}

// IsInfected 是否检出病毒.
func (r *ScanResult) IsInfected() bool { return !r.Clean }

// parseScanResp 把 clamd 响应解析成 ScanResult.
//
// 响应格式 (zSCAN):
//
//	"/path/file: OK\x00"
//	"/path/file: Eicar-Test-Signature FOUND\x00"
//	"/path/file: ERROR <msg>\x00"
func parseScanResp(s string) (*ScanResult, error) {
	s = strings.TrimRight(s, "\x00\n")
	colonIdx := strings.LastIndex(s, ": ")
	if colonIdx < 0 {
		return nil, fmt.Errorf("invalid clamd resp: %q", s)
	}
	path := s[:colonIdx]
	body := s[colonIdx+2:]
	r := &ScanResult{Path: path, Raw: s}
	switch {
	case strings.HasSuffix(body, " FOUND"):
		r.VirusName = strings.TrimSuffix(body, " FOUND")
	case body == "OK":
		r.Clean = true
	case strings.HasPrefix(body, "ERROR"):
		return r, errors.New("clamd: " + body)
	default:
		return nil, fmt.Errorf("clamd unknown body: %q", body)
	}
	return r, nil
}
