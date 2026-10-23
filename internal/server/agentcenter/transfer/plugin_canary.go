package transfer

import (
	"context"

	"go.uber.org/zap"

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
func (s *Service) buildPluginConfigs(pluginConfigs []model.PluginConfig, canaries map[string]model.PluginCanary,
	agentID string, runtimeType model.RuntimeType) []*grpcProto.Config {
	var configs []*grpcProto.Config
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
	return configs
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
