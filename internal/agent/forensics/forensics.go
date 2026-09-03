// Package forensics provides remote forensic capabilities for the Agent.
// Server can request file retrieval and command execution on agents for
// incident response purposes. All actions are audited.
//
// Safety:
//   - Command execution is restricted to an allowlist of read-only inspection
//     programs, parsed into argv and executed without a shell
//   - Command execution has timeout (default 30s, max 5min)
//   - File retrieval has size limit (default 50MB)
//   - All operations logged to audit trail
package forensics

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	maxFileSize    = 50 * 1024 * 1024 // 50MB
	defaultTimeout = 30 * time.Second
	maxTimeout     = 5 * time.Minute
)

// Handler processes forensic commands from the Server.
type Handler struct {
	logger  *zap.Logger
	workDir string
}

// NewHandler creates a forensics handler.
func NewHandler(logger *zap.Logger, workDir string) *Handler {
	return &Handler{
		logger:  logger,
		workDir: workDir,
	}
}

// Request is a forensic action request from the Server.
type Request struct {
	Action    string `json:"action"`     // "file_get" | "cmd_exec"
	Path      string `json:"path"`       // file path (for file_get)
	Command   string `json:"command"`    // shell command (for cmd_exec)
	TimeoutS  int    `json:"timeout_s"`  // command timeout in seconds
	RequestID string `json:"request_id"` // tracking ID
}

// Response is the result of a forensic action.
type Response struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`

	// File retrieval results.
	FileName string `json:"file_name,omitempty"`
	FileSize int64  `json:"file_size,omitempty"`
	FileSHA  string `json:"file_sha256,omitempty"`
	FileData string `json:"file_data,omitempty"` // base64 encoded

	// Command execution results.
	ExitCode int    `json:"exit_code,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Duration int    `json:"duration_ms,omitempty"`
}

// Handle processes a forensic request and returns the response.
func (h *Handler) Handle(ctx context.Context, data string) (*Response, error) {
	var req Request
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		return nil, fmt.Errorf("parse forensic request: %w", err)
	}

	h.logger.Info("forensic request received",
		zap.String("request_id", req.RequestID),
		zap.String("action", req.Action))

	var resp *Response

	switch req.Action {
	case "file_get":
		resp = h.handleFileGet(req)
	case "cmd_exec":
		resp = h.handleCmdExec(ctx, req)
	default:
		resp = &Response{
			RequestID: req.RequestID,
			Action:    req.Action,
			Error:     fmt.Sprintf("unknown forensic action: %s", req.Action),
		}
	}

	h.logger.Info("forensic request completed",
		zap.String("request_id", req.RequestID),
		zap.String("action", req.Action),
		zap.Bool("success", resp.Success))

	return resp, nil
}

func (h *Handler) handleFileGet(req Request) *Response {
	resp := &Response{
		RequestID: req.RequestID,
		Action:    req.Action,
	}

	if req.Path == "" {
		resp.Error = "file path is required"
		return resp
	}

	// 规范化并要求绝对路径：消除 ".." 穿越歧义，强制服务端显式指定目标。
	// 取证是经 mTLS 认证 + 审计的管理动作，按设计可读任意文件，故此处只做路径卫生而非白名单。
	cleanPath := filepath.Clean(req.Path)
	if !filepath.IsAbs(cleanPath) {
		resp.Error = "file path must be absolute"
		return resp
	}
	req.Path = cleanPath

	info, err := os.Stat(req.Path)
	if err != nil {
		resp.Error = fmt.Sprintf("stat file: %v", err)
		return resp
	}

	if info.IsDir() {
		resp.Error = "path is a directory, not a file"
		return resp
	}

	if info.Size() > maxFileSize {
		resp.Error = fmt.Sprintf("file too large: %d bytes (max %d)", info.Size(), maxFileSize)
		return resp
	}

	f, err := os.Open(req.Path)
	if err != nil {
		resp.Error = fmt.Sprintf("open file: %v", err)
		return resp
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		resp.Error = fmt.Sprintf("read file: %v", err)
		return resp
	}

	hash := sha256.Sum256(data)

	resp.Success = true
	resp.FileName = info.Name()
	resp.FileSize = info.Size()
	resp.FileSHA = hex.EncodeToString(hash[:])
	resp.FileData = base64.StdEncoding.EncodeToString(data)

	return resp
}

func (h *Handler) handleCmdExec(ctx context.Context, req Request) *Response {
	resp := &Response{
		RequestID: req.RequestID,
		Action:    req.Action,
	}

	if req.Command == "" {
		resp.Error = "command is required"
		return resp
	}

	// 白名单校验：只允许枚举内的只读取证程序，并解析为 argv 后不经 shell 执行。
	argv, err := ParseForensicArgv(req.Command)
	if err != nil {
		resp.Error = fmt.Sprintf("command rejected by forensic exec policy: %v", err)
		h.logger.Warn("[AUDIT] forensic command rejected",
			zap.String("request_id", req.RequestID),
			zap.String("command", req.Command),
			zap.Error(err))
		return resp
	}
	h.logger.Info("[AUDIT] forensic command accepted",
		zap.String("request_id", req.RequestID),
		zap.Strings("argv", argv))

	timeout := defaultTimeout
	if req.TimeoutS > 0 {
		timeout = time.Duration(req.TimeoutS) * time.Second
		if timeout > maxTimeout {
			timeout = maxTimeout
		}
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(cmdCtx, argv[0], argv[1:]...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	duration := time.Since(start)

	resp.Duration = int(duration.Milliseconds())
	resp.Stdout = truncateOutput(stdout.String(), 1024*1024) // 1MB max output
	resp.Stderr = truncateOutput(stderr.String(), 64*1024)   // 64KB max stderr

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			resp.ExitCode = exitErr.ExitCode()
		} else {
			resp.Error = err.Error()
			return resp
		}
	}

	resp.Success = true
	return resp
}

func truncateOutput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}
