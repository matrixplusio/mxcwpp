package transfer

import (
	"context"
	"errors"
	neturl "net/url"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// loadPluginCanaries 读取全部插件灰度，按插件名索引。读失败按「没有灰度」处理：
// 灰度主机暂时回到全局版本，不会因为一次查询失败让整机插件下发中断。
func (s *Service) loadPluginCanaries() map[string]model.PluginCanary {
	var rows []model.PluginCanary
	if err := s.db.Find(&rows).Error; err != nil {
		s.logger.Warn("读取插件灰度失败，按全局版本下发", zap.Error(err))
		return nil
	}
	out := make(map[string]model.PluginCanary, len(rows))
	for _, r := range rows {
		out[r.PluginName] = r
	}
	return out
}

// buildPluginConfigs 为一台 agent 构造插件配置：按运行时过滤，灰度名单内的主机换成灰度版本。
// 连接时下发与广播共用这一处，没有灰度记录时输出与原先逐字一致。
// archHint 是本次连接首包心跳里上报的架构（可为空）：新主机首次连接时主机记录还没写入，
// 只能靠它，否则 arm64 主机第一次必然拿到 amd64 的哈希且不会自动重发。
// 返回错误时调用方不应下发：用默认（amd64）内容顶替会让运行中的其他架构插件被停掉重装。
func (s *Service) buildPluginConfigs(pluginConfigs []model.PluginConfig, canaries map[string]model.PluginCanary,
	agentID string, runtimeType model.RuntimeType, archHint string) ([]*grpcProto.Config, error) {
	var configs []*grpcProto.Config
	arch := normalizeArch(archHint)
	if arch == "" {
		var err error
		if arch, err = s.getAgentArch(agentID); err != nil {
			return nil, err
		}
	}
	for _, pc := range pluginConfigs {
		// RuntimeTypes 为空 = 兼容旧数据，全平台发
		if len(pc.RuntimeTypes) > 0 && !containsString([]string(pc.RuntimeTypes), string(runtimeType)) {
			continue
		}
		if c, ok := canaries[pc.Name]; ok && c.Covers(agentID) {
			pc.Version = c.Version
			pc.SHA256 = c.SHA256
			pc.Signature = c.Signature
			pc.DownloadURLs = model.StringArray{model.PluginCanaryDownloadURL(pc.Name, c.Version)}
		}
		if err := s.applyArchPackage(&pc, arch); err != nil {
			return nil, err
		}

		downloadURLs, sha256 := s.resolvePluginDelivery(pc)
		if len(downloadURLs) == 0 {
			continue
		}
		configs = append(configs, &grpcProto.Config{
			Name:         pc.Name,
			Type:         string(pc.Type),
			Version:      pc.Version,
			Sha256:       sha256,
			Signature:    pc.Signature,
			DownloadUrls: downloadURLs,
			Detail:       pc.Detail,
		})
	}
	return configs, nil
}

// ResendPluginConfigs 给本实例上的指定 agent 重发插件配置（灰度开始、回滚、转正后立即生效）。
// 不在本实例上的 agent 忽略——manager 向每台 AC 都发同一份请求。返回实际发出的数量。
func (s *Service) ResendPluginConfigs(ctx context.Context, agentIDs []string) int {
	sent := 0
	for _, id := range agentIDs {
		s.connMu.RLock()
		conn, ok := s.connections[id]
		s.connMu.RUnlock()
		if !ok {
			continue
		}
		if err := s.sendPluginConfigsIfNeeded(ctx, conn, s.getAgentRuntimeType(id)); err != nil {
			s.logger.Warn("重发插件配置失败", zap.String("agent_id", id), zap.Error(err))
			continue
		}
		sent++
	}
	return sent
}

// getAgentArch 返回主机架构（amd64 / arm64）。没有主机记录时返回空串，调用方保持默认（amd64）内容；
// 查询出错时返回错误——不能当成「没有记录」，否则数据库抖动时其他架构的主机会收到 amd64 的哈希。
func (s *Service) getAgentArch(agentID string) (string, error) {
	if s.db == nil || agentID == "" {
		return "", nil
	}
	var host model.Host
	err := s.db.Select("arch").Where("host_id = ?", agentID).First(&host).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return normalizeArch(host.Arch), nil
}

// normalizeArch 统一 uname 与 Go 两种写法，和组件包登记用的架构名对齐。
func normalizeArch(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "x86_64", "amd64", "x64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(a))
	}
}

// applyArchPackage 把插件配置的哈希与签名换成主机架构对应的那个包的。
//
// 插件配置只存一份（优先 amd64）的哈希与签名；不换的话，其他架构的主机下载到自己架构的包后
// 哈希对不上，插件被拒绝加载。以下情况保持原值：找不到对应包；平台启用了签名而这个包没有签名
// （绝不把一个架构的签名配上另一个架构的哈希）；下载地址不是平台自己的端点（外部地址只有一份文件，
// 不分架构）。查询出错时返回错误，由调用方放弃本次下发。
func (s *Service) applyArchPackage(pc *model.PluginConfig, arch string) error {
	if arch == "" || s.db == nil || pc.Version == "" || !usesPlatformDownload(pc.DownloadURLs) {
		return nil
	}
	var pkg model.ComponentPackage
	err := s.db.Model(&model.ComponentPackage{}).
		Select("component_packages.sha256, component_packages.signature").
		Joins("JOIN component_versions ON component_versions.id = component_packages.version_id AND component_versions.deleted_at IS NULL").
		Joins("JOIN components ON components.id = component_versions.component_id AND components.deleted_at IS NULL").
		Where("components.name = ? AND components.category = ? AND component_versions.version = ?",
			pc.Name, model.ComponentCategoryPlugin, pc.Version).
		Where("component_packages.arch = ? AND component_packages.enabled = ? AND component_packages.pkg_type IN ?",
			arch, true, []model.PackageType{model.PackageTypeBinary, model.PackageTypeTGZ}).
		First(&pkg).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if pkg.SHA256 == "" || pkg.SHA256 == pc.SHA256 {
		return nil
	}
	if pc.Signature != "" && pkg.Signature == "" {
		s.logger.Warn("插件该架构的包没有签名，保持默认下发内容（该主机会拒绝加载）；重新同步插件配置可补签",
			zap.String("plugin", pc.Name), zap.String("version", pc.Version), zap.String("arch", arch))
		return nil
	}
	pc.SHA256 = pkg.SHA256
	pc.Signature = pkg.Signature
	return nil
}

// usesPlatformDownload 判断插件是否从平台自己的下载端点取包：只有这个端点按 arch 参数分架构返回。
// 只看 URL 的路径部分，与 agent 端补 arch 参数的判断（internal/agent/plugin.withArchParam）口径一致。
func usesPlatformDownload(urls model.StringArray) bool {
	for _, raw := range urls {
		if u, err := neturl.Parse(raw); err == nil && strings.Contains(u.Path, "/api/v1/plugins/download/") {
			return true
		}
	}
	return false
}
