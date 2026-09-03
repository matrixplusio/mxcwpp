// Package api 提供 HTTP API 处理器
package api

import (
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// PluginsHandler 处理插件相关请求
type PluginsHandler struct {
	logger     *zap.Logger
	pluginsDir string
	uploadDir  string // 上传目录（优先从这里读取）
}

// NewPluginsHandler 创建 PluginsHandler 实例
func NewPluginsHandler(logger *zap.Logger, pluginsDir string) *PluginsHandler {
	return &PluginsHandler{
		logger:     logger,
		pluginsDir: pluginsDir,
		uploadDir:  "./uploads/plugins", // 默认上传插件目录
	}
}

// DownloadPlugin 下载插件文件
// GET /api/v1/plugins/download/:name
// 支持 ?arch=amd64|arm64 参数指定架构
func (h *PluginsHandler) DownloadPlugin(c *gin.Context) {
	pluginName := c.Param("name")
	arch := c.Query("arch") // 可选的架构参数

	// 安全检查：防止路径遍历
	if pluginName == "" || pluginName == "." || pluginName == ".." ||
		filepath.Base(pluginName) != pluginName {
		BadRequest(c, "无效的插件名称")
		return
	}

	// 验证架构参数（如果提供）
	if arch != "" && arch != "amd64" && arch != "arm64" {
		BadRequest(c, "无效的架构参数，支持: amd64, arm64")
		return
	}

	var pluginPath string
	var found bool

	// 优先从上传目录查找（支持架构参数）
	if arch != "" {
		// 尝试查找 {name}_{arch} 格式的文件
		uploadPath := filepath.Join(h.uploadDir, pluginName+"_"+arch)
		if info, err := os.Stat(uploadPath); err == nil && !info.IsDir() {
			pluginPath = uploadPath
			found = true
		}
	}

	// 如果没有指定架构或没找到，尝试不带架构的文件名
	if !found {
		uploadPath := filepath.Join(h.uploadDir, pluginName)
		if info, err := os.Stat(uploadPath); err == nil && !info.IsDir() {
			pluginPath = uploadPath
			found = true
		}
	}

	// 如果上传目录没找到，从默认插件目录查找
	if !found {
		if arch != "" {
			// 尝试 {arch}/{name} 格式（编译输出的目录结构）
			defaultPath := filepath.Join(h.pluginsDir, arch, pluginName)
			if info, err := os.Stat(defaultPath); err == nil && !info.IsDir() {
				pluginPath = defaultPath
				found = true
			}
		}
		// 尝试直接在 pluginsDir 下查找
		if !found {
			defaultPath := filepath.Join(h.pluginsDir, pluginName)
			if info, err := os.Stat(defaultPath); err == nil && !info.IsDir() {
				pluginPath = defaultPath
				found = true
			}
		}
	}

	if !found {
		h.logger.Warn("插件文件不存在",
			zap.String("plugin_name", pluginName),
			zap.String("arch", arch),
			zap.String("upload_dir", h.uploadDir),
			zap.String("plugins_dir", h.pluginsDir),
		)
		NotFound(c, "插件不存在")
		return
	}

	fileInfo, err := os.Stat(pluginPath)
	if err != nil {
		h.logger.Error("读取插件文件信息失败",
			zap.String("plugin_path", pluginPath),
			zap.Error(err),
		)
		InternalError(c, "读取插件文件失败")
		return
	}

	h.logger.Info("下载插件",
		zap.String("plugin_name", pluginName),
		zap.String("arch", arch),
		zap.String("plugin_path", pluginPath),
		zap.Int64("file_size", fileInfo.Size()),
	)

	// 设置响应头
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename="+pluginName)

	// 发送文件
	c.File(pluginPath)
}

// ListPlugins 列出可用插件
// GET /api/v1/plugins
func (h *PluginsHandler) ListPlugins(c *gin.Context) {
	// 读取插件目录
	entries, err := os.ReadDir(h.pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			Success(c, []interface{}{})
			return
		}
		h.logger.Error("读取插件目录失败",
			zap.String("plugins_dir", h.pluginsDir),
			zap.Error(err),
		)
		InternalError(c, "读取插件目录失败")
		return
	}

	type PluginInfo struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}

	var plugins []PluginInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		plugins = append(plugins, PluginInfo{
			Name: entry.Name(),
			Size: info.Size(),
		})
	}

	Success(c, plugins)
}
