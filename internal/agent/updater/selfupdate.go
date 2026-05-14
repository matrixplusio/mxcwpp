// Package updater 实现 Agent 自更新功能
// selfupdate.go 提供 CLI 主动更新能力（mxsec-agent --update）
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// UpdateCheckResponse 更新检查 API 的响应
type UpdateCheckResponse struct {
	Code int              `json:"code"`
	Data *UpdateCheckData `json:"data,omitempty"`
}

// UpdateCheckData 更新检查数据
type UpdateCheckData struct {
	HasUpdate      bool   `json:"has_update"`
	LatestVersion  string `json:"latest_version"`
	CurrentVersion string `json:"current_version"`
	DownloadURL    string `json:"download_url"`
	SHA256         string `json:"sha256"`
	PkgType        string `json:"pkg_type"`
	Arch           string `json:"arch"`
	FileSize       int64  `json:"file_size"`
}

// SelfUpdateOptions CLI 更新选项
type SelfUpdateOptions struct {
	ServerHost     string // 编译时嵌入的 gRPC 地址（如 10.0.0.1:6751）
	ServerHTTP     string // 用户指定的 HTTP 地址（--server flag，覆盖推导）
	CurrentVersion string // 当前版本
	WorkDir        string // 工作目录
	Force          bool   // 强制更新
	LocalFile      string // 本地包文件路径（离线模式）
}

// RunSelfUpdate 执行 CLI 主动更新
func RunSelfUpdate(opts SelfUpdateOptions) error {
	// 检查 root 权限
	if os.Getuid() != 0 {
		return fmt.Errorf("需要 root 权限执行更新，请使用 sudo 运行")
	}

	// 本地文件模式
	if opts.LocalFile != "" {
		return runLocalFileUpdate(opts)
	}

	// 远程更新模式
	return runRemoteUpdate(opts)
}

// runLocalFileUpdate 使用本地包文件更新
func runLocalFileUpdate(opts SelfUpdateOptions) error {
	filePath := opts.LocalFile

	// 验证文件存在
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("包文件不存在: %w", err)
	}

	// 从文件扩展名检测包类型
	pkgType := detectPkgTypeFromFile(filePath)
	if pkgType == "" {
		return fmt.Errorf("无法识别包类型，文件必须以 .rpm 或 .deb 结尾: %s", filePath)
	}

	fmt.Printf("本地文件更新模式\n")
	fmt.Printf("  包文件: %s\n", filePath)
	fmt.Printf("  包类型: %s\n", pkgType)
	fmt.Printf("  文件大小: %.2f MB\n", float64(info.Size())/(1024*1024))
	fmt.Printf("  当前版本: %s\n\n", opts.CurrentVersion)

	// 安装
	fmt.Printf("正在安装...\n")
	output, err := InstallPackage(pkgType, filePath)
	if err != nil {
		return fmt.Errorf("安装失败: %w", err)
	}
	if output != "" {
		fmt.Printf("  %s\n", output)
	}

	fmt.Printf("安装完成，正在重启 Agent 服务...\n")
	RestartAgent()

	// 等待一小段时间让用户看到输出
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("Agent 将在 2 秒后重启\n")
	return nil
}

// runRemoteUpdate 从 Server 拉取更新
func runRemoteUpdate(opts SelfUpdateOptions) error {
	// 推导 Server HTTP 地址
	serverURL, err := resolveServerHTTPURL(opts.ServerHost, opts.ServerHTTP)
	if err != nil {
		return fmt.Errorf("无法确定 Server 地址: %w", err)
	}

	// 检测本机包类型和架构
	pkgType := DetectPkgType()
	if pkgType == "" {
		return fmt.Errorf("无法检测本机包管理器类型（需要 rpm 或 dpkg）")
	}
	arch := GetCurrentArch()

	fmt.Printf("检查更新...\n")
	fmt.Printf("  Server: %s\n", serverURL)
	fmt.Printf("  当前版本: %s\n", opts.CurrentVersion)
	fmt.Printf("  系统架构: %s\n", arch)
	fmt.Printf("  包类型: %s\n\n", pkgType)

	// 调用 update-check API
	checkURL := fmt.Sprintf("%s/api/v1/agent/update-check?arch=%s&current_version=%s&pkg_type=%s",
		serverURL, arch, opts.CurrentVersion, pkgType)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("连接 Server 失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Server 返回错误 (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var checkResp UpdateCheckResponse
	if err := json.Unmarshal(body, &checkResp); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}

	if checkResp.Data == nil {
		return fmt.Errorf("Server 返回数据为空")
	}

	data := checkResp.Data

	// 判断是否需要更新
	if !data.HasUpdate && !opts.Force {
		fmt.Printf("当前已是最新版本 (%s)，无需更新\n", opts.CurrentVersion)
		return nil
	}

	if !data.HasUpdate && opts.Force {
		fmt.Printf("当前已是最新版本 (%s)，强制重新安装\n", opts.CurrentVersion)
	} else {
		fmt.Printf("发现新版本: %s → %s\n", opts.CurrentVersion, data.LatestVersion)
	}
	fmt.Printf("  包类型: %s, 架构: %s\n", data.PkgType, data.Arch)
	fmt.Printf("  文件大小: %.2f MB\n", float64(data.FileSize)/(1024*1024))
	fmt.Printf("  SHA256: %s\n\n", data.SHA256)

	// 创建临时目录
	tmpDir := filepath.Join(opts.WorkDir, "update_tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// 构建完整下载 URL
	downloadURL := data.DownloadURL
	if !strings.HasPrefix(downloadURL, "http") {
		downloadURL = serverURL + downloadURL
	}

	pkgFileName := fmt.Sprintf("mxsec-agent-%s.%s", data.LatestVersion, data.PkgType)
	pkgPath := filepath.Join(tmpDir, pkgFileName)

	// 下载
	fmt.Printf("正在下载 %s ...\n", pkgFileName)
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	written, err := DownloadFile(dlCtx, downloadURL, pkgPath)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	fmt.Printf("  已下载 %.2f MB\n", float64(written)/(1024*1024))

	// SHA256 校验
	fmt.Printf("正在校验 SHA256...\n")
	actualSHA256, err := CalculateSHA256(pkgPath)
	if err != nil {
		return fmt.Errorf("计算 SHA256 失败: %w", err)
	}

	if !strings.EqualFold(actualSHA256, data.SHA256) {
		return fmt.Errorf("SHA256 校验失败: 期望 %s, 实际 %s", data.SHA256, actualSHA256)
	}
	fmt.Printf("  校验通过\n\n")

	// 安装
	fmt.Printf("正在安装...\n")
	output, err := InstallPackage(data.PkgType, pkgPath)
	if err != nil {
		return fmt.Errorf("安装失败: %w", err)
	}
	if output != "" {
		fmt.Printf("  %s\n", output)
	}

	fmt.Printf("安装完成，正在重启 Agent 服务...\n")
	RestartAgent()

	time.Sleep(500 * time.Millisecond)
	fmt.Printf("Agent 将在 2 秒后重启\n")
	return nil
}

// resolveServerHTTPURL 推导 Server HTTP 地址
// 优先使用用户指定的 --server，否则从编译时嵌入的 gRPC 地址推导
func resolveServerHTTPURL(grpcHost, userOverride string) (string, error) {
	// 用户显式指定
	if userOverride != "" {
		return strings.TrimSuffix(userOverride, "/"), nil
	}

	// 从 gRPC 地址推导
	if grpcHost == "" {
		return "", fmt.Errorf("未嵌入 Server 地址，请使用 --server 指定")
	}

	host, _, err := net.SplitHostPort(grpcHost)
	if err != nil {
		// 可能没有端口，直接使用
		host = grpcHost
	}

	// 默认 Manager HTTP 端口 8080
	return fmt.Sprintf("http://%s:8080", host), nil
}

// detectPkgTypeFromFile 从文件扩展名检测包类型
func detectPkgTypeFromFile(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".rpm":
		return "rpm"
	case ".deb":
		return "deb"
	default:
		return ""
	}
}
