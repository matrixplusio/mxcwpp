// Package api 提供 HTTP API 处理器
package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AgentHandler 是 Agent 安装脚本 API 处理器
type AgentHandler struct {
	logger      *zap.Logger
	serverHost  string // AgentCenter gRPC 地址（例如：10.0.0.1:6751）
	httpAddress string // Manager HTTP 地址（例如：10.0.0.1:8080）
}

// NewAgentHandler 创建 Agent 安装脚本处理器
func NewAgentHandler(logger *zap.Logger, serverHost, httpAddress string) *AgentHandler {
	return &AgentHandler{
		logger:      logger,
		serverHost:  serverHost,
		httpAddress: httpAddress,
	}
}

// InstallScript 返回 Linux 安装脚本
// GET /agent/install.sh
func (h *AgentHandler) InstallScript(c *gin.Context) {
	// 读取安装脚本
	scriptContent, err := h.readInstallScript()
	if err != nil {
		h.logger.Error("读取安装脚本失败", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to read install script")
		return
	}

	// 从请求中获取 HTTP 服务器地址（优先使用请求的 Host，否则使用配置的地址）
	httpHost := c.GetHeader("Host")
	if httpHost == "" {
		// 如果 Host 头为空，尝试从 X-Forwarded-Host 获取（代理场景）
		httpHost = c.GetHeader("X-Forwarded-Host")
	}
	if httpHost == "" {
		// 如果还是为空，使用配置的地址
		httpHost = h.httpAddress
		// 如果配置的地址是 0.0.0.0 或 localhost，尝试从请求中获取实际地址
		if strings.Contains(httpHost, "0.0.0.0") || strings.Contains(httpHost, "localhost") || strings.Contains(httpHost, "127.0.0.1") {
			// 尝试从 X-Forwarded-For 或 RemoteAddr 获取客户端 IP（作为服务器地址的参考）
			// 但更可靠的方式是使用 Host 头（如果存在）
			// 如果都没有，保持使用配置的地址（可能是开发环境）
		}
	}
	// 确保有协议前缀
	if !strings.HasPrefix(httpHost, "http://") && !strings.HasPrefix(httpHost, "https://") {
		// 根据请求协议决定使用 http 还是 https
		scheme := "http"
		if c.GetHeader("X-Forwarded-Proto") == "https" || c.Request.TLS != nil {
			scheme = "https"
		}
		httpHost = scheme + "://" + httpHost
	}
	// 提取 host:port 部分（去掉协议）
	httpHostOnly := httpHost
	if strings.HasPrefix(httpHostOnly, "http://") {
		httpHostOnly = strings.TrimPrefix(httpHostOnly, "http://")
	} else if strings.HasPrefix(httpHostOnly, "https://") {
		httpHostOnly = strings.TrimPrefix(httpHostOnly, "https://")
	}

	// 获取 Agent Server 地址（gRPC 地址）
	// 如果配置的地址是 0.0.0.0，使用 HTTP Host 的 host 部分 + gRPC 端口
	agentServerHost := h.serverHost
	if strings.Contains(agentServerHost, "0.0.0.0") {
		// 从 httpHostOnly 中提取 host 部分（去掉端口）
		hostPart := httpHostOnly
		if idx := strings.LastIndex(httpHostOnly, ":"); idx > 0 {
			hostPart = httpHostOnly[:idx]
		}
		// 从 serverHost 中提取端口部分
		portPart := "6751"
		if idx := strings.LastIndex(h.serverHost, ":"); idx > 0 {
			portPart = h.serverHost[idx+1:]
		}
		agentServerHost = hostPart + ":" + portPart
	}

	// 替换脚本中的占位符
	// 1. 替换 Agent Server 地址占位符（用于 Agent 连接）
	scriptContent = strings.ReplaceAll(scriptContent, "AGENT_SERVER_PLACEHOLDER", agentServerHost)
	scriptContent = strings.ReplaceAll(scriptContent, "${MXSEC_AGENT_SERVER:-AGENT_SERVER_PLACEHOLDER}", agentServerHost)

	// 2. 替换 HTTP Server 地址占位符（用于下载安装包）
	scriptContent = strings.ReplaceAll(scriptContent, "http://SERVER_HOST_PLACEHOLDER", httpHost)
	scriptContent = strings.ReplaceAll(scriptContent, "SERVER_HOST_PLACEHOLDER", httpHostOnly)
	// 兼容旧的占位符格式
	scriptContent = strings.ReplaceAll(scriptContent, "http://${SERVER_HOST}/api/v1/agent/download", fmt.Sprintf("%s/api/v1/agent/download", httpHost))

	// 设置响应头
	c.Header("Content-Type", "text/x-shellscript; charset=utf-8")
	c.Header("Content-Disposition", "inline; filename=install.sh")
	c.String(http.StatusOK, scriptContent)
}

// UninstallScript 返回 Linux 卸载脚本
// GET /agent/uninstall.sh
func (h *AgentHandler) UninstallScript(c *gin.Context) {
	// 读取卸载脚本
	scriptContent, err := h.readUninstallScript()
	if err != nil {
		h.logger.Error("读取卸载脚本失败", zap.Error(err))
		c.String(http.StatusInternalServerError, "Failed to read uninstall script")
		return
	}

	// 设置响应头
	c.Header("Content-Type", "text/x-shellscript; charset=utf-8")
	c.Header("Content-Disposition", "inline; filename=uninstall.sh")
	c.String(http.StatusOK, scriptContent)
}

// readInstallScript 读取安装脚本内容
func (h *AgentHandler) readInstallScript() (string, error) {
	// 尝试从文件系统读取（相对于工作目录或可执行文件目录）
	possiblePaths := []string{
		"scripts/install.sh",
		"./scripts/install.sh",
		"/opt/mxsec-platform/scripts/install.sh",
		filepath.Join(filepath.Dir(os.Args[0]), "scripts/install.sh"),
	}

	for _, path := range possiblePaths {
		if data, err := os.ReadFile(path); err == nil {
			h.logger.Debug("成功读取安装脚本", zap.String("path", path))
			return string(data), nil
		}
	}

	// 如果都失败，返回默认脚本
	h.logger.Warn("无法从文件系统读取安装脚本，使用默认脚本")
	return h.getDefaultInstallScript(), nil
}

// readUninstallScript 读取卸载脚本内容
func (h *AgentHandler) readUninstallScript() (string, error) {
	// 尝试从文件系统读取
	possiblePaths := []string{
		"scripts/uninstall.sh",
		"./scripts/uninstall.sh",
		"/opt/mxsec-platform/scripts/uninstall.sh",
		filepath.Join(filepath.Dir(os.Args[0]), "scripts/uninstall.sh"),
	}

	for _, path := range possiblePaths {
		if data, err := os.ReadFile(path); err == nil {
			h.logger.Debug("成功读取卸载脚本", zap.String("path", path))
			return string(data), nil
		}
	}

	// 如果文件不存在，返回默认卸载脚本
	h.logger.Warn("无法从文件系统读取卸载脚本，使用默认脚本")
	return h.getDefaultUninstallScript(), nil
}

// getDefaultInstallScript 返回默认安装脚本（如果文件读取失败时的后备方案）
func (h *AgentHandler) getDefaultInstallScript() string {
	return `#!/bin/bash
# Matrix Cloud Security Platform Agent 一键安装脚本
# 使用方法: curl -sS http://SERVER_IP:8080/agent/install.sh | bash

set -e

echo "Matrix Cloud Security Platform Agent Installer"
echo "Please ensure install.sh is properly configured."
`
}

// getDefaultUninstallScript 返回默认卸载脚本
func (h *AgentHandler) getDefaultUninstallScript() string {
	return `#!/bin/bash
# Matrix Cloud Security Platform Agent 卸载脚本
# 使用方法: curl -sS http://SERVER_IP:8080/agent/uninstall.sh | bash

set -e

echo "Matrix Cloud Security Platform Agent Uninstaller"
echo "Please ensure uninstall.sh is properly configured."
`
}
