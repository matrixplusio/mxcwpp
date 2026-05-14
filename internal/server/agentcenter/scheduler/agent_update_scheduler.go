// Package scheduler 提供任务调度器
package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
	"github.com/imkerbos/mxsec-platform/internal/server/agentcenter/transfer"
	"github.com/imkerbos/mxsec-platform/internal/server/config"
	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// AgentUpdateScheduler Agent 更新调度器
// 定期检查是否有新版本的 Agent，并推送给需要更新的 Agent
type AgentUpdateScheduler struct {
	db              *gorm.DB
	transferService *transfer.Service
	cfg             *config.Config
	logger          *zap.Logger
	lastCheckTime   time.Time
	mu              sync.Mutex
}

// NewAgentUpdateScheduler 创建 Agent 更新调度器
func NewAgentUpdateScheduler(db *gorm.DB, transferService *transfer.Service, cfg *config.Config, logger *zap.Logger) *AgentUpdateScheduler {
	return &AgentUpdateScheduler{
		db:              db,
		transferService: transferService,
		cfg:             cfg,
		logger:          logger,
		lastCheckTime:   time.Now(),
	}
}

// getBackendURL 从数据库获取后端接口地址配置
func (s *AgentUpdateScheduler) getBackendURL() string {
	var config model.SystemConfig
	if err := s.db.Where("`key` = ? AND category = ?", "site_config", "site").First(&config).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			s.logger.Debug("查询系统配置失败，将使用备选URL方案",
				zap.String("key", "site_config"),
				zap.Error(err))
		} else {
			s.logger.Debug("系统配置不存在，请在 系统管理-基本设置 中配置后端接口地址",
				zap.String("key", "site_config"))
		}
		return ""
	}

	if config.Value == "" {
		s.logger.Debug("系统配置值为空，将使用备选URL方案",
			zap.String("key", "site_config"))
		return ""
	}

	var siteConfig model.SiteConfig
	if err := json.Unmarshal([]byte(config.Value), &siteConfig); err != nil {
		s.logger.Warn("解析站点配置失败", zap.Error(err))
		return ""
	}

	if siteConfig.BackendURL != "" {
		s.logger.Debug("成功从系统配置读取后端地址",
			zap.String("backend_url", siteConfig.BackendURL))
	} else {
		s.logger.Debug("系统配置中后端地址为空，将使用备选URL方案")
	}

	return siteConfig.BackendURL
}

// buildDownloadURL 构建完整的下载 URL
// 优先级：后端接口地址 > GRPC Host > localhost
func (s *AgentUpdateScheduler) buildDownloadURL(pkgType model.PackageType, arch string) string {
	// 构建相对路径
	relativePath := fmt.Sprintf("/api/v1/agent/download/%s/%s", pkgType, arch)

	// 优先级1: 从数据库获取后端接口地址配置（系统管理-基本设置-后端接口地址）
	backendURL := s.getBackendURL()
	if backendURL != "" {
		// 后端接口地址已包含协议和端口（如果有），直接拼接路径
		// 去除末尾的斜杠
		backendURL = strings.TrimSuffix(backendURL, "/")
		fullURL := backendURL + relativePath
		s.logger.Info("使用系统配置的后端地址构建下载URL",
			zap.String("source", "system_config"),
			zap.String("backend_url", backendURL),
			zap.String("download_url", fullURL))
		return fullURL
	}

	// 优先级2: 使用 GRPC Host（如果不是 0.0.0.0）
	// Agent 编译时会嵌入 server_host（如 "agentcenter:6751"），同理我们用 GRPC 配置的主机名
	httpPort := s.cfg.Server.HTTP.Port
	grpcHost := s.cfg.Server.GRPC.Host
	if grpcHost != "0.0.0.0" && grpcHost != "" {
		fullURL := fmt.Sprintf("http://%s:%d%s", grpcHost, httpPort, relativePath)
		s.logger.Info("使用GRPC Host构建下载URL",
			zap.String("source", "grpc_host"),
			zap.String("grpc_host", grpcHost),
			zap.Int("http_port", httpPort),
			zap.String("download_url", fullURL))
		return fullURL
	}

	// 优先级3: localhost（最后回退，仅开发环境）
	fullURL := fmt.Sprintf("http://localhost:%d%s", httpPort, relativePath)
	s.logger.Warn("未配置后端接口地址且 GRPC Host 为 0.0.0.0，使用 localhost（仅用于开发环境）",
		zap.String("source", "localhost_fallback"),
		zap.String("download_url", fullURL),
		zap.String("建议", "在 系统管理-基本设置 中配置后端接口地址（如 http://manager:8080 或 http://192.168.x.x:8080）"))
	return fullURL
}

func (s *AgentUpdateScheduler) isAutoUpdateCandidate(host model.Host) bool {
	version := strings.TrimSpace(strings.ToLower(host.AgentVersion))
	return version != "dev"
}

func (s *AgentUpdateScheduler) packageFileExists(pkg model.ComponentPackage) bool {
	if pkg.FilePath == "" {
		return false
	}
	if info, err := os.Stat(pkg.FilePath); err == nil && !info.IsDir() {
		return true
	}
	return false
}

// Start 启动 Agent 更新调度器
func (s *AgentUpdateScheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // 每 30 秒检查一次
	defer ticker.Stop()

	s.logger.Info("Agent 更新调度器已启动", zap.Duration("interval", 30*time.Second))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Agent 更新调度器已停止")
			return
		case <-ticker.C:
			s.checkAndPushUpdates(ctx)
		}
	}
}

// checkAndPushUpdates 检查并推送 Agent 更新
func (s *AgentUpdateScheduler) checkAndPushUpdates(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Debug("开始检查 Agent 更新")

	// 优先处理 pending 状态的推送记录（手动触发的推送）
	var pendingRecords []model.ComponentPushRecord
	if err := s.db.Where("component_name = ? AND status = ?", "agent", model.ComponentPushStatusPending).
		Order("created_at ASC").Find(&pendingRecords).Error; err != nil {
		s.logger.Error("查询 pending 推送记录失败", zap.Error(err))
		return
	}

	s.logger.Debug("查询到 pending 推送记录", zap.Int("count", len(pendingRecords)))

	if len(pendingRecords) > 0 {
		for _, record := range pendingRecords {
			s.logger.Info("开始处理推送记录",
				zap.Uint("record_id", record.ID),
				zap.String("version", record.Version),
				zap.Int("total_count", record.TotalCount))
			s.processPushRecord(ctx, &record)
		}
		return // 处理完 pending 记录后返回，下次再检查自动更新
	}

	// 如果没有 pending 记录，执行自动更新检查
	s.autoCheckAndPushUpdates(ctx)
}

// processPushRecord 处理单个推送记录
func (s *AgentUpdateScheduler) processPushRecord(ctx context.Context, pushRecord *model.ComponentPushRecord) {
	// 更新状态为 pushing
	s.db.Model(pushRecord).Update("status", model.ComponentPushStatusPushing)

	// 查找对应版本（必须是 agent 组件的版本）
	var latestVersion model.ComponentVersion
	if err := s.db.Where("component_id = ? AND version = ?", pushRecord.ComponentID, pushRecord.Version).First(&latestVersion).Error; err != nil {
		s.logger.Error("查询版本失败", zap.Error(err), zap.Uint("component_id", pushRecord.ComponentID))
		s.db.Model(pushRecord).Updates(map[string]interface{}{
			"status":  model.ComponentPushStatusFailed,
			"message": "查询版本失败: " + err.Error(),
		})
		return
	}

	// 查询目标主机
	var hosts []model.Host
	query := s.db.Where("status = ?", model.HostStatusOnline)
	if len(pushRecord.TargetHosts) > 0 {
		// 将 StringArray 转换为 []string 以便 GORM 正确处理 IN 子句
		targetHostIDs := []string(pushRecord.TargetHosts)
		query = query.Where("host_id IN ?", targetHostIDs)
	}
	if err := query.Find(&hosts).Error; err != nil {
		s.logger.Error("查询主机失败", zap.Error(err))
		s.db.Model(pushRecord).Updates(map[string]interface{}{
			"status":  model.ComponentPushStatusFailed,
			"message": "查询主机失败: " + err.Error(),
		})
		return
	}

	successCount := 0
	failedCount := 0
	var failedHostIDs []string

	for _, host := range hosts {
		if !pushRecord.Force && !s.isAutoUpdateCandidate(host) {
			s.logger.Debug("跳过 dev 版本 Agent 自动更新",
				zap.String("host_id", host.HostID),
				zap.String("agent_version", host.AgentVersion))
			continue
		}

		// 检查是否需要更新（考虑 force 标志）
		if !pushRecord.Force && host.AgentVersion != "" && host.AgentVersion == latestVersion.Version {
			// 版本相同且不强制更新，跳过
			continue
		}

		// 根据主机的架构和 OS 查找对应的包
		pkgType := s.detectPackageType(host.OSFamily)
		arch := host.Arch
		if arch == "" {
			arch = "amd64"
		}

		var pkg model.ComponentPackage
		if err := s.db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
			latestVersion.ID, pkgType, arch, true).First(&pkg).Error; err != nil {
			s.logger.Debug("未找到对应的 Agent 包",
				zap.String("host_id", host.HostID),
				zap.String("pkg_type", string(pkgType)),
				zap.String("arch", arch),
				zap.Error(err))
			failedCount++
			failedHostIDs = append(failedHostIDs, host.HostID)
			continue
		}
		if !s.packageFileExists(pkg) {
			s.logger.Warn("Agent 更新包文件不存在，跳过推送",
				zap.String("host_id", host.HostID),
				zap.String("version", latestVersion.Version),
				zap.String("path", pkg.FilePath))
			failedCount++
			failedHostIDs = append(failedHostIDs, host.HostID)
			continue
		}

		// 构建完整下载 URL
		downloadURL := s.buildDownloadURL(pkgType, arch)

		// 构建更新命令
		agentUpdate := &grpcProto.AgentUpdate{
			Version:     latestVersion.Version,
			DownloadUrl: downloadURL,
			Sha256:      pkg.SHA256,
			PkgType:     string(pkg.PkgType),
			Arch:        pkg.Arch,
			Force:       pushRecord.Force, // 使用推送记录中的 force 标志
		}

		cmd := &grpcProto.Command{
			AgentUpdate: agentUpdate,
		}

		// 发送更新命令
		if err := s.transferService.SendCommand(host.HostID, cmd); err != nil {
			s.logger.Warn("推送 Agent 更新失败",
				zap.String("host_id", host.HostID),
				zap.String("version", latestVersion.Version),
				zap.Error(err))
			failedCount++
			failedHostIDs = append(failedHostIDs, host.HostID)
			continue
		}

		s.logger.Info("已推送 Agent 更新",
			zap.String("host_id", host.HostID),
			zap.String("old_version", host.AgentVersion),
			zap.String("new_version", latestVersion.Version),
			zap.Bool("force", pushRecord.Force),
			zap.String("download_url", downloadURL))

		successCount++
	}

	// 更新推送记录的最终状态
	now := model.ToLocalTime(time.Now())
	updates := map[string]interface{}{
		"success_count": successCount,
		"failed_count":  failedCount,
		"failed_hosts":  model.StringArray(failedHostIDs),
		"completed_at":  &now,
	}

	if failedCount == 0 && successCount > 0 {
		updates["status"] = model.ComponentPushStatusSuccess
		updates["message"] = fmt.Sprintf("推送完成，成功 %d 台", successCount)
	} else if successCount == 0 {
		updates["status"] = model.ComponentPushStatusFailed
		updates["message"] = fmt.Sprintf("推送失败，失败 %d 台", failedCount)
	} else {
		updates["status"] = model.ComponentPushStatusSuccess
		updates["message"] = fmt.Sprintf("推送完成，成功 %d 台，失败 %d 台", successCount, failedCount)
	}

	s.db.Model(pushRecord).Updates(updates)

	s.logger.Info("推送记录处理完成",
		zap.Uint("record_id", pushRecord.ID),
		zap.Int("success_count", successCount),
		zap.Int("failed_count", failedCount))
}

// autoCheckAndPushUpdates 自动检查并推送 Agent 更新（原有逻辑）
// 注意：调用方 checkAndPushUpdates 已持有 s.mu 锁，此处不可重复加锁
func (s *AgentUpdateScheduler) autoCheckAndPushUpdates(ctx context.Context) {
	// 查找 agent 组件的最新版本
	var agentComponent model.Component
	if err := s.db.Where("name = ? AND category = ?", "agent", model.ComponentCategoryAgent).First(&agentComponent).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logger.Debug("未找到 Agent 组件，跳过更新检查")
			return
		}
		s.logger.Error("查询 Agent 组件失败", zap.Error(err))
		return
	}

	// 查找最新版本
	var latestVersion model.ComponentVersion
	if err := s.db.Where("component_id = ? AND is_latest = ?", agentComponent.ID, true).First(&latestVersion).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logger.Debug("未找到 Agent 最新版本，跳过更新检查")
			return
		}
		s.logger.Error("查询 Agent 最新版本失败", zap.Error(err))
		return
	}

	// 查询所有在线的主机，检查是否需要更新
	var hosts []model.Host
	if err := s.db.Where("status = ?", model.HostStatusOnline).Find(&hosts).Error; err != nil {
		s.logger.Error("查询在线主机失败", zap.Error(err))
		return
	}

	if len(hosts) == 0 {
		return
	}

	// 比较版本并推送更新
	updatedCount := 0
	var targetHostIDs []string
	var failedHostIDs []string

	for _, host := range hosts {
		if !s.isAutoUpdateCandidate(host) {
			continue
		}

		// 如果主机没有版本信息，或者版本不同，则推送更新
		if host.AgentVersion == "" || host.AgentVersion != latestVersion.Version {
			targetHostIDs = append(targetHostIDs, host.HostID)

			// 根据主机的架构和 OS 查找对应的包
			pkgType := s.detectPackageType(host.OSFamily)
			arch := host.Arch
			if arch == "" {
				arch = "amd64" // 默认架构
			}

			// 查找对应的包
			var pkg model.ComponentPackage
			if err := s.db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
				latestVersion.ID, pkgType, arch, true).First(&pkg).Error; err != nil {
				s.logger.Debug("未找到对应的 Agent 包",
					zap.String("host_id", host.HostID),
					zap.String("pkg_type", string(pkgType)),
					zap.String("arch", arch),
					zap.Error(err))
				failedHostIDs = append(failedHostIDs, host.HostID)
				continue
			}
			if !s.packageFileExists(pkg) {
				s.logger.Debug("Agent 更新包文件不存在，跳过自动推送",
					zap.String("host_id", host.HostID),
					zap.String("version", latestVersion.Version),
					zap.String("path", pkg.FilePath))
				failedHostIDs = append(failedHostIDs, host.HostID)
				continue
			}

			// 构建完整下载 URL
			downloadURL := s.buildDownloadURL(pkgType, arch)

			// 构建更新命令
			agentUpdate := &grpcProto.AgentUpdate{
				Version:     latestVersion.Version,
				DownloadUrl: downloadURL,
				Sha256:      pkg.SHA256,
				PkgType:     string(pkg.PkgType),
				Arch:        pkg.Arch,
				Force:       false,
			}

			cmd := &grpcProto.Command{
				AgentUpdate: agentUpdate,
			}

			// 发送更新命令
			if err := s.transferService.SendCommand(host.HostID, cmd); err != nil {
				s.logger.Warn("推送 Agent 更新失败",
					zap.String("host_id", host.HostID),
					zap.String("version", latestVersion.Version),
					zap.Error(err))
				failedHostIDs = append(failedHostIDs, host.HostID)
				continue
			}

			s.logger.Info("已推送 Agent 更新",
				zap.String("host_id", host.HostID),
				zap.String("old_version", host.AgentVersion),
				zap.String("new_version", latestVersion.Version),
				zap.String("download_url", downloadURL))

			updatedCount++
		}
	}

	if updatedCount > 0 || len(failedHostIDs) > 0 {
		s.logger.Info("Agent 更新检查完成",
			zap.Int("total_hosts", len(hosts)),
			zap.Int("updated_count", updatedCount),
			zap.Int("failed_count", len(failedHostIDs)),
			zap.String("latest_version", latestVersion.Version))

		// 更新推送记录（查找最近的 pending 记录）
		var pushRecord model.ComponentPushRecord
		if err := s.db.Where("component_name = ? AND version = ? AND status IN ?", "agent", latestVersion.Version, []model.ComponentPushStatus{model.ComponentPushStatusPending, model.ComponentPushStatusPushing}).
			Order("created_at DESC").First(&pushRecord).Error; err == nil {
			// 更新推送记录
			successCount := updatedCount
			failedCount := len(failedHostIDs)
			updates := map[string]interface{}{
				"status":        model.ComponentPushStatusPushing,
				"target_hosts":  model.StringArray(targetHostIDs),
				"total_count":   len(targetHostIDs),
				"success_count": successCount,
				"failed_count":  failedCount,
				"failed_hosts":  model.StringArray(failedHostIDs),
			}
			if successCount+failedCount >= len(targetHostIDs) {
				// 推送完成
				now := model.ToLocalTime(time.Now())
				updates["status"] = model.ComponentPushStatusSuccess
				updates["completed_at"] = &now
				if failedCount > 0 {
					updates["status"] = model.ComponentPushStatusFailed
				}
			}
			s.db.Model(&pushRecord).Updates(updates)
		}
	}

	s.lastCheckTime = time.Now()
}

// detectPackageType 根据 OS 类型检测包类型
func (s *AgentUpdateScheduler) detectPackageType(osFamily string) model.PackageType {
	switch osFamily {
	case "rocky", "centos", "rhel", "oracle", "almalinux":
		return model.PackageTypeRPM
	case "debian", "ubuntu":
		return model.PackageTypeDEB
	default:
		// 默认使用二进制
		return model.PackageTypeBinary
	}
}

// TriggerUpdate 手动触发 Agent 更新（供 API 调用）
func (s *AgentUpdateScheduler) TriggerUpdate(ctx context.Context, hostIDs []string) (int, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 查找 agent 组件的最新版本
	var agentComponent model.Component
	if err := s.db.Where("name = ? AND category = ?", "agent", model.ComponentCategoryAgent).First(&agentComponent).Error; err != nil {
		return 0, nil, fmt.Errorf("查询 Agent 组件失败: %w", err)
	}

	var latestVersion model.ComponentVersion
	if err := s.db.Where("component_id = ? AND is_latest = ?", agentComponent.ID, true).First(&latestVersion).Error; err != nil {
		return 0, nil, fmt.Errorf("查询 Agent 最新版本失败: %w", err)
	}

	// 查询指定的主机
	var hosts []model.Host
	query := s.db.Where("status = ?", model.HostStatusOnline)
	if len(hostIDs) > 0 {
		query = query.Where("host_id IN ?", hostIDs)
	}
	if err := query.Find(&hosts).Error; err != nil {
		return 0, nil, fmt.Errorf("查询主机失败: %w", err)
	}

	if len(hosts) == 0 {
		return 0, nil, nil
	}

	successCount := 0
	var failedAgents []string

	for _, host := range hosts {
		// 根据主机的架构和 OS 查找对应的包
		pkgType := s.detectPackageType(host.OSFamily)
		arch := host.Arch
		if arch == "" {
			arch = "amd64"
		}

		// 查找对应的包
		var pkg model.ComponentPackage
		if err := s.db.Where("version_id = ? AND pkg_type = ? AND arch = ? AND enabled = ?",
			latestVersion.ID, pkgType, arch, true).First(&pkg).Error; err != nil {
			failedAgents = append(failedAgents, host.HostID)
			s.logger.Warn("未找到对应的 Agent 包",
				zap.String("host_id", host.HostID),
				zap.String("pkg_type", string(pkgType)),
				zap.String("arch", arch))
			continue
		}
		if !s.packageFileExists(pkg) {
			failedAgents = append(failedAgents, host.HostID)
			s.logger.Warn("Agent 更新包文件不存在",
				zap.String("host_id", host.HostID),
				zap.String("version", latestVersion.Version),
				zap.String("path", pkg.FilePath))
			continue
		}

		// 构建完整下载 URL
		downloadURL := s.buildDownloadURL(pkgType, arch)

		// 构建更新命令
		agentUpdate := &grpcProto.AgentUpdate{
			Version:     latestVersion.Version,
			DownloadUrl: downloadURL,
			Sha256:      pkg.SHA256,
			PkgType:     string(pkg.PkgType),
			Arch:        pkg.Arch,
			Force:       true, // 手动推送时强制更新
		}

		cmd := &grpcProto.Command{
			AgentUpdate: agentUpdate,
		}

		// 发送更新命令
		if err := s.transferService.SendCommand(host.HostID, cmd); err != nil {
			failedAgents = append(failedAgents, host.HostID)
			s.logger.Warn("推送 Agent 更新失败",
				zap.String("host_id", host.HostID),
				zap.Error(err))
			continue
		}

		successCount++
		s.logger.Info("已手动推送 Agent 更新",
			zap.String("host_id", host.HostID),
			zap.String("version", latestVersion.Version),
			zap.String("download_url", downloadURL))
	}

	// 更新推送记录（查找最近的 pending 记录）
	if successCount > 0 || len(failedAgents) > 0 {
		var pushRecord model.ComponentPushRecord
		if err := s.db.Where("component_name = ? AND version = ? AND status = ?", "agent", latestVersion.Version, model.ComponentPushStatusPending).
			Order("created_at DESC").First(&pushRecord).Error; err == nil {
			// 更新推送记录
			updates := map[string]interface{}{
				"status":        model.ComponentPushStatusPushing,
				"success_count": successCount,
				"failed_count":  len(failedAgents),
				"failed_hosts":  model.StringArray(failedAgents),
			}
			if successCount+len(failedAgents) >= pushRecord.TotalCount {
				// 推送完成
				now := model.ToLocalTime(time.Now())
				updates["status"] = model.ComponentPushStatusSuccess
				updates["completed_at"] = &now
				if len(failedAgents) > 0 {
					updates["status"] = model.ComponentPushStatusFailed
				}
			}
			s.db.Model(&pushRecord).Updates(updates)
		}
	}

	return successCount, failedAgents, nil
}
