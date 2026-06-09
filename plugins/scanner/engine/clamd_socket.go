package engine

// ClamdSocketScanner 通过 clamd UNIX socket 调用守护进程扫描。
//
// 与 ClamAVScanner (基于 clamscan CLI) 区别:
//   - clamscan CLI: 每次启动加载 ~1GB 病毒库, 单文件扫描 5-15s
//   - clamd socket: 守护进程常驻 + 病毒库内存, 单文件扫描 ~10ms
//
// 协议参考: clamd manual (https://docs.clamav.net/manual/Usage/Services.html)
//
// 命令格式 (尾部 \0 终止):
//
//	zPING\0              → PONG\0  (心跳)
//	zVERSION\0           → ClamAV 1.x.x/...\0
//	zINSTREAM\0          → 接收数据流 (4字节 BE 长度 + 数据, 0 长结束)
//	zSCAN <path>\0       → <path>: <signature> FOUND\0 或 OK
//	zMULTISCAN <dir>\0   → 并发扫整目录
//
// 子进程隔离 (避免 GPL 传染):
//
//	mxsec 通过 socket IPC 与 clamd 交互, 不 link libclamav。
//	clamd 由系统自带安装 (apt/yum install clamav-daemon), 走标准 systemd 服务。

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// 默认 clamd socket 路径 (Debian/Ubuntu 标准位置)。
const (
	defaultClamdSocket  = "/var/run/clamav/clamd.ctl"
	clamdConnectTimeout = 3 * time.Second
	clamdScanTimeout    = 60 * time.Second
)

// ClamdSocketScanner 基于 clamd UNIX socket 的扫描器。
type ClamdSocketScanner struct {
	socketPath string
	logger     *zap.Logger
}

// NewClamdSocketScanner 构造。socketPath 为空时用系统默认路径。
func NewClamdSocketScanner(socketPath string, logger *zap.Logger) *ClamdSocketScanner {
	if logger == nil {
		logger = zap.NewNop()
	}
	if socketPath == "" {
		socketPath = defaultClamdSocket
	}
	return &ClamdSocketScanner{socketPath: socketPath, logger: logger}
}

// Available 检查 socket 是否可连且 clamd 响应 PING。
func (s *ClamdSocketScanner) Available() bool {
	if _, err := os.Stat(s.socketPath); err != nil {
		return false
	}
	conn, err := s.dial()
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := writeCommand(conn, "PING"); err != nil {
		return false
	}
	resp, err := readResponse(conn)
	if err != nil {
		return false
	}
	return strings.TrimSpace(resp) == "PONG"
}

// Version 返回 clamd 版本字符串。
func (s *ClamdSocketScanner) Version() (string, error) {
	conn, err := s.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := writeCommand(conn, "VERSION"); err != nil {
		return "", err
	}
	return readResponse(conn)
}

// ScanFile 扫描指定路径。返回签名命中名 (FOUND) 或空 (OK)。
//
// path 必须是 clamd 进程可读路径 (注意 clamd 通常以 clamav 用户运行,
// 路径需 ACL 允许)。
func (s *ClamdSocketScanner) ScanFile(ctx context.Context, path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("clamd scan: file stat: %w", err)
	}
	conn, err := s.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	} else {
		_ = conn.SetDeadline(time.Now().Add(clamdScanTimeout))
	}
	if err := writeCommand(conn, "SCAN "+path); err != nil {
		return "", err
	}
	resp, err := readResponse(conn)
	if err != nil {
		return "", err
	}
	return parseScanResponse(resp)
}

// ScanStream 把内存 buffer 通过 INSTREAM 上传给 clamd 扫描。
//
// 适用场景: 远程下载的临时数据、内存解压后的 payload、
// clamd 没权限读的路径。
func (s *ClamdSocketScanner) ScanStream(ctx context.Context, r io.Reader) (string, error) {
	conn, err := s.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	} else {
		_ = conn.SetDeadline(time.Now().Add(clamdScanTimeout))
	}
	if err := writeCommand(conn, "INSTREAM"); err != nil {
		return "", err
	}
	// 分块上传, 单块 ≤ 1MB
	buf := make([]byte, 64*1024)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, werr := conn.Write(lenBuf); werr != nil {
				return "", werr
			}
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return "", werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	// 0 长终止
	endBuf := make([]byte, 4)
	if _, err := conn.Write(endBuf); err != nil {
		return "", err
	}
	resp, err := readResponse(conn)
	if err != nil {
		return "", err
	}
	return parseScanResponse(resp)
}

// Selfcheck 写 EICAR 到临时文件 → 扫描 → 期望命中。
//
// 部署后跑一次确认 clamd 通路 + 病毒库就绪。
func (s *ClamdSocketScanner) Selfcheck(ctx context.Context) error {
	if !s.Available() {
		return errors.New("clamd socket unavailable")
	}
	tmp, err := os.CreateTemp("", ".mxsec_clamd_selfcheck_*.txt")
	if err != nil {
		return fmt.Errorf("selfcheck create: %w", err)
	}
	defer os.Remove(tmp.Name())
	// EICAR test signature (标准业界自检样本)
	eicar := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	if _, err := tmp.WriteString(eicar); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("selfcheck write: %w", err)
	}
	_ = tmp.Close()
	sig, err := s.ScanFile(ctx, tmp.Name())
	if err != nil {
		return fmt.Errorf("selfcheck scan: %w", err)
	}
	if sig == "" {
		return errors.New("selfcheck did not hit EICAR (clamd virus DB stale?)")
	}
	s.logger.Info("clamd selfcheck OK", zap.String("signature", sig))
	return nil
}

func (s *ClamdSocketScanner) dial() (net.Conn, error) {
	return net.DialTimeout("unix", s.socketPath, clamdConnectTimeout)
}

// writeCommand 写 clamd 命令 (z<CMD>\0 模式, null 终止).
func writeCommand(conn net.Conn, cmd string) error {
	_, err := conn.Write([]byte("z" + cmd + "\x00"))
	return err
}

func readResponse(conn net.Conn) (string, error) {
	rd := bufio.NewReader(conn)
	line, err := rd.ReadString(0) // null-terminated
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\x00"), nil
}

// parseScanResponse 解析 SCAN/INSTREAM 响应。
//
// 命中: "/path/file: signature_name FOUND"
// 干净: "/path/file: OK" 或 "stream: OK"
// 错误: "/path/file: error_msg ERROR"
func parseScanResponse(resp string) (string, error) {
	resp = strings.TrimSpace(resp)
	if strings.HasSuffix(resp, " OK") {
		return "", nil
	}
	if strings.HasSuffix(resp, " ERROR") {
		return "", fmt.Errorf("clamd error: %s", resp)
	}
	if strings.HasSuffix(resp, " FOUND") {
		// /path/file: signature_name FOUND
		idx := strings.LastIndex(resp, ": ")
		if idx < 0 {
			return "", fmt.Errorf("malformed FOUND response: %s", resp)
		}
		body := resp[idx+2:]
		// trim " FOUND"
		sig := strings.TrimSuffix(body, " FOUND")
		return strings.TrimSpace(sig), nil
	}
	return "", fmt.Errorf("unknown clamd response: %s", resp)
}
