package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

const (
	// 病毒库更新间隔（每 4 小时）
	virusDBUpdateInterval = 4 * time.Hour
	// 分布式锁 key
	virusDBLockKey = "mxsec:virusdb:update:lock"
	virusDBLockTTL = 10 * time.Minute
	// 病毒库组件名称
	virusDBComponentName = "virus-database"
)

// VirusDBUpdater Server 端病毒库更新器
// 定时运行 freshclam 更新 ClamAV 病毒库，通过组件管理系统分发到 Agent
type VirusDBUpdater struct {
	db             *gorm.DB
	redisClient    *redis.Client
	logger         *zap.Logger
	dataDir        string // 病毒库存储目录
	uploadDir      string // 组件上传目录
	pluginsBaseURL string // 插件下载基础 URL（用于 PluginConfig 下载地址）
	triggerCh      chan struct{}
	// fileHashes 记录上一次发布时每个病毒库文件的 SHA256，用于文件级 Delta 检测
	fileHashes map[string]string // filename -> sha256
}

// NewVirusDBUpdater 创建病毒库更新器
func NewVirusDBUpdater(db *gorm.DB, redisClient *redis.Client, logger *zap.Logger, dataDir, uploadDir, pluginsBaseURL string) *VirusDBUpdater {
	absDataDir, _ := filepath.Abs(dataDir)
	absUploadDir, _ := filepath.Abs(uploadDir)
	// freshclam 在 Alpine 下固定写入 /var/lib/clamav，直接使用该目录
	dbDir := "/var/lib/clamav"
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		logger.Error("创建病毒库目录失败", zap.Error(err))
	}
	// 保留 absDataDir 用于 uploads 等其他用途
	_ = absDataDir
	return &VirusDBUpdater{
		db:             db,
		redisClient:    redisClient,
		logger:         logger,
		dataDir:        dbDir,
		uploadDir:      absUploadDir,
		pluginsBaseURL: pluginsBaseURL,
		triggerCh:      make(chan struct{}, 1),
		fileHashes:     make(map[string]string),
	}
}

// Start 启动定时更新循环
func (u *VirusDBUpdater) Start(ctx context.Context) {
	ticker := time.NewTicker(virusDBUpdateInterval)
	defer ticker.Stop()

	u.logger.Info("病毒库更新器已启动",
		zap.Duration("interval", virusDBUpdateInterval),
		zap.String("data_dir", u.dataDir),
	)

	// 初始化文件 hash 基线，避免重启后误判所有文件为"变化"
	u.initFileHashes()

	// 启动时执行一次
	u.runOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			u.logger.Info("病毒库更新器已停止")
			return
		case <-ticker.C:
			u.runOnce(ctx)
		case <-u.triggerCh:
			u.logger.Info("收到手动触发信号，开始同步病毒库")
			u.runOnce(ctx)
		}
	}
}

// TriggerSync 手动触发一次同步（非阻塞）
func (u *VirusDBUpdater) TriggerSync() bool {
	select {
	case u.triggerCh <- struct{}{}:
		return true
	default:
		return false // 已有触发在排队
	}
}

// GetLatestStatus 查询最近一条同步记录
func (u *VirusDBUpdater) GetLatestStatus(dbType string) (*model.SecurityDBSyncRecord, error) {
	var record model.SecurityDBSyncRecord
	err := u.db.Where("db_type = ?", dbType).Order("id DESC").First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &record, nil
}

// GetSyncHistory 分页查询同步历史记录
func (u *VirusDBUpdater) GetSyncHistory(dbType string, page, pageSize int) ([]model.SecurityDBSyncRecord, int64, error) {
	var total int64
	query := u.db.Model(&model.SecurityDBSyncRecord{}).Where("db_type = ?", dbType)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var records []model.SecurityDBSyncRecord
	offset := (page - 1) * pageSize
	err := query.Offset(offset).Limit(pageSize).Order("id DESC").Find(&records).Error
	return records, total, err
}

// runOnce 执行一次病毒库更新
func (u *VirusDBUpdater) runOnce(ctx context.Context) {
	// 前置检查：freshclam 不存在则跳过，不报错
	if _, err := exec.LookPath("freshclam"); err != nil {
		u.logger.Warn("freshclam 未安装，跳过病毒库更新（如需启用请在容器中安装 clamav）")
		return
	}

	if !u.acquireLock(ctx) {
		return
	}
	defer u.releaseLock(ctx)

	startedAt := time.Now()

	// 插入 running 记录
	record := model.SecurityDBSyncRecord{
		DBType:    "clamav",
		Status:    "running",
		StartedAt: startedAt,
	}
	u.db.Create(&record)

	u.logger.Info("开始更新病毒库...")

	// 1. 运行 freshclam 更新病毒库
	if err := u.runFreshclam(ctx); err != nil {
		u.logger.Error("freshclam 更新失败", zap.Error(err))
		u.finishRecord(&record, "", 0, "", startedAt, err)
		return
	}

	// 2. 检查是否有病毒库文件
	patterns := []string{"*.cvd", "*.cld"}
	var hasDBFiles bool
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(u.dataDir, pattern))
		if len(matches) > 0 {
			hasDBFiles = true
			break
		}
	}
	if !hasDBFiles {
		err := fmt.Errorf("freshclam 执行成功但 %s 下无 .cvd/.cld 文件", u.dataDir)
		u.logger.Error("病毒库文件缺失", zap.String("data_dir", u.dataDir), zap.Error(err))
		u.finishRecord(&record, "", 0, "", startedAt, err)
		return
	}

	// 3. 文件级 Delta 检测：只打包实际有变化的文件
	changedFiles, allHashes := u.detectChangedFiles()
	if len(changedFiles) == 0 {
		u.logger.Info("病毒库文件无变化，跳过打包发布")
		u.finishRecord(&record, "", 0, "", startedAt, nil)
		return
	}

	u.logger.Info("检测到病毒库文件变化",
		zap.Int("changed_files", len(changedFiles)),
		zap.Strings("files", changedFiles))

	// 4. 打包变化的文件（增量包）
	archivePath, version, err := u.packageVirusDBDelta(changedFiles)
	if err != nil {
		u.logger.Error("打包病毒库失败", zap.Error(err))
		u.finishRecord(&record, "", 0, "", startedAt, err)
		return
	}

	// 5. 计算文件信息
	sha256Hash, fileSize, _ := u.fileSHA256(archivePath)

	// 6. 发布为组件新版本
	if err := u.publishVersion(archivePath, version); err != nil {
		u.logger.Error("发布病毒库版本失败", zap.Error(err))
		u.finishRecord(&record, version, fileSize, sha256Hash, startedAt, err)
		return
	}

	// 7. 更新文件 hash 缓存
	u.fileHashes = allHashes

	// 8. 清理旧版本文件（保留最近 5 个）
	u.cleanupOldVersions(5)

	u.finishRecord(&record, version, fileSize, sha256Hash, startedAt, nil)
	u.logger.Info("病毒库增量更新完成",
		zap.String("version", version),
		zap.Int64("size", fileSize),
		zap.Int("changed_files", len(changedFiles)))
}

// finishRecord 更新同步记录的最终状态
func (u *VirusDBUpdater) finishRecord(record *model.SecurityDBSyncRecord, version string, fileSize int64, sha256Hash string, startedAt time.Time, syncErr error) {
	duration := int(time.Since(startedAt).Seconds())
	updates := map[string]interface{}{
		"duration": duration,
	}

	if syncErr != nil {
		updates["status"] = "failed"
		updates["error_msg"] = syncErr.Error()
	} else {
		updates["status"] = "success"
		updates["version"] = version
		updates["file_size"] = fileSize
		updates["sha256"] = sha256Hash
	}

	if err := u.db.Model(record).Updates(updates).Error; err != nil {
		u.logger.Error("更新同步记录失败", zap.Error(err))
	}
}

// runFreshclam 运行 freshclam 更新病毒库
func (u *VirusDBUpdater) runFreshclam(ctx context.Context) error {
	freshclamBin, err := exec.LookPath("freshclam")
	if err != nil {
		return fmt.Errorf("freshclam not found in PATH: %w", err)
	}

	// 直接使用 Alpine 默认配置，数据写入 /var/lib/clamav
	args := []string{"--foreground"}

	cmd := exec.CommandContext(ctx, freshclamBin, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		u.logger.Warn("freshclam 输出", zap.String("output", string(output)))
		return fmt.Errorf("freshclam failed: %w", err)
	}

	u.logger.Info("freshclam 更新成功", zap.String("output", string(output)))
	return nil
}

// packageVirusDB 将病毒库文件打包为 tar.gz
func (u *VirusDBUpdater) packageVirusDB() (string, string, error) {
	// 查找 .cvd 和 .cld 文件
	patterns := []string{"*.cvd", "*.cld"}
	var dbFiles []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(u.dataDir, pattern))
		if err != nil {
			continue
		}
		dbFiles = append(dbFiles, matches...)
	}

	if len(dbFiles) == 0 {
		return "", "", fmt.Errorf("no virus database files found in %s", u.dataDir)
	}

	// 版本号：使用时间戳
	version := time.Now().Format("20060102.150405")

	// 打包
	archiveName := fmt.Sprintf("virus-database-%s.tar.gz", version)
	archivePath := filepath.Join(u.uploadDir, "plugins", archiveName)

	if err := os.MkdirAll(filepath.Dir(archivePath), 0755); err != nil {
		return "", "", err
	}

	// 使用 tar 命令打包（简单可靠）
	args := []string{"-czf", archivePath, "-C", u.dataDir}
	for _, f := range dbFiles {
		args = append(args, filepath.Base(f))
	}

	cmd := exec.Command("tar", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("tar failed: %s: %w", string(output), err)
	}

	u.logger.Info("病毒库打包完成",
		zap.String("archive", archivePath),
		zap.Int("files", len(dbFiles)),
	)

	return archivePath, version, nil
}

// initFileHashes 启动时扫描当前病毒库文件，建立 hash 基线
// 避免每次重启后 fileHashes 为空导致所有文件被误判为"变化"并重新打包
func (u *VirusDBUpdater) initFileHashes() {
	patterns := []string{"*.cvd", "*.cld"}
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(u.dataDir, pattern))
		for _, filePath := range matches {
			filename := filepath.Base(filePath)
			hash, _, err := u.fileSHA256(filePath)
			if err != nil {
				u.logger.Warn("初始化病毒库 hash 失败", zap.String("file", filename), zap.Error(err))
				continue
			}
			u.fileHashes[filename] = hash
		}
	}
	if len(u.fileHashes) > 0 {
		u.logger.Info("病毒库 hash 基线已建立", zap.Int("files", len(u.fileHashes)))
	}
}

// detectChangedFiles 检测病毒库文件中哪些发生了变化
// 返回变化的文件名列表和当前所有文件的 hash map
func (u *VirusDBUpdater) detectChangedFiles() ([]string, map[string]string) {
	patterns := []string{"*.cvd", "*.cld"}
	var allFiles []string
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(u.dataDir, pattern))
		allFiles = append(allFiles, matches...)
	}

	currentHashes := make(map[string]string, len(allFiles))
	var changedFiles []string

	for _, filePath := range allFiles {
		filename := filepath.Base(filePath)
		hash, _, err := u.fileSHA256(filePath)
		if err != nil {
			u.logger.Warn("计算文件 SHA256 失败", zap.String("file", filename), zap.Error(err))
			changedFiles = append(changedFiles, filename)
			continue
		}
		currentHashes[filename] = hash

		if oldHash, ok := u.fileHashes[filename]; !ok || oldHash != hash {
			changedFiles = append(changedFiles, filename)
		}
	}

	return changedFiles, currentHashes
}

// packageVirusDBDelta 只打包指定的变化文件
func (u *VirusDBUpdater) packageVirusDBDelta(changedFiles []string) (string, string, error) {
	if len(changedFiles) == 0 {
		return "", "", fmt.Errorf("no changed files to package")
	}

	version := time.Now().Format("20060102.150405")
	archiveName := fmt.Sprintf("virus-database-%s.tar.gz", version)
	archivePath := filepath.Join(u.uploadDir, "plugins", archiveName)

	if err := os.MkdirAll(filepath.Dir(archivePath), 0755); err != nil {
		return "", "", err
	}

	args := []string{"-czf", archivePath, "-C", u.dataDir}
	args = append(args, changedFiles...)

	cmd := exec.Command("tar", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("tar failed: %s: %w", string(output), err)
	}

	u.logger.Info("病毒库增量打包完成",
		zap.String("archive", archivePath),
		zap.Int("changed_files", len(changedFiles)),
		zap.Strings("files", changedFiles),
	)

	return archivePath, version, nil
}

// cleanupOldVersions 清理旧版本的病毒库 tar.gz 文件
// keep: 保留最近的 N 个版本
func (u *VirusDBUpdater) cleanupOldVersions(keep int) {
	var component model.Component
	if err := u.db.Where("name = ?", virusDBComponentName).First(&component).Error; err != nil {
		return
	}

	// 查询所有非最新版本，按创建时间倒序
	var oldVersions []model.ComponentVersion
	if err := u.db.Where("component_id = ? AND is_latest = ?", component.ID, false).
		Order("created_at DESC").
		Find(&oldVersions).Error; err != nil {
		u.logger.Error("查询旧版本失败", zap.Error(err))
		return
	}

	// 保留最近 keep-1 个旧版本（加上当前最新版共 keep 个）
	if len(oldVersions) <= keep-1 {
		return
	}

	toDelete := oldVersions[keep-1:]
	deletedCount := 0
	for _, ver := range toDelete {
		// 查找关联的包文件并删除
		var pkgs []model.ComponentPackage
		u.db.Where("version_id = ?", ver.ID).Find(&pkgs)
		for _, pkg := range pkgs {
			if pkg.FilePath != "" {
				if err := os.Remove(pkg.FilePath); err != nil && !os.IsNotExist(err) {
					u.logger.Warn("删除旧版本文件失败", zap.String("path", pkg.FilePath), zap.Error(err))
				}
			}
		}
		// 删除数据库记录
		u.db.Where("version_id = ?", ver.ID).Delete(&model.ComponentPackage{})
		u.db.Delete(&ver)
		deletedCount++
	}

	if deletedCount > 0 {
		u.logger.Info("清理旧版本完成",
			zap.Int("deleted", deletedCount),
			zap.Int("kept", keep))
	}
}

// publishVersion 将病毒库发布为组件新版本
func (u *VirusDBUpdater) publishVersion(archivePath, version string) error {
	// 确保组件存在
	var component model.Component
	result := u.db.Where("name = ?", virusDBComponentName).First(&component)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// 自动创建组件
			component = model.Component{
				Name:        virusDBComponentName,
				Category:    model.ComponentCategory("plugin"),
				Description: "ClamAV 病毒库（自动更新）",
				CreatedBy:   "system",
			}
			if err := u.db.Create(&component).Error; err != nil {
				return fmt.Errorf("create component: %w", err)
			}
			u.logger.Info("自动创建病毒库组件", zap.Uint("id", component.ID))
		} else {
			return fmt.Errorf("query component: %w", result.Error)
		}
	}

	// 计算 SHA256
	sha256Hash, fileSize, err := u.fileSHA256(archivePath)
	if err != nil {
		return fmt.Errorf("calculate sha256: %w", err)
	}

	// 将旧版本的 is_latest 设为 false
	u.db.Model(&model.ComponentVersion{}).
		Where("component_id = ? AND is_latest = ?", component.ID, true).
		Update("is_latest", false)

	// 创建新版本
	cv := model.ComponentVersion{
		ComponentID: component.ID,
		Version:     version,
		IsLatest:    true,
		CreatedBy:   "system",
	}

	if err := u.db.Create(&cv).Error; err != nil {
		return fmt.Errorf("create version: %w", err)
	}

	// 创建包记录
	pkg := model.ComponentPackage{
		VersionID:  cv.ID,
		OS:         "linux",
		Arch:       "all",
		PkgType:    model.PackageType("binary"),
		FilePath:   archivePath,
		FileName:   filepath.Base(archivePath),
		FileSize:   fileSize,
		SHA256:     sha256Hash,
		Enabled:    true,
		UploadedBy: "system",
	}

	if err := u.db.Create(&pkg).Error; err != nil {
		return fmt.Errorf("create package: %w", err)
	}

	u.logger.Info("病毒库版本发布成功",
		zap.String("version", version),
		zap.String("sha256", sha256Hash),
		zap.Int64("size", fileSize),
	)

	// 同步 PluginConfig，使 PluginUpdateScheduler 能广播到 Agent
	if err := u.syncPluginConfig(version, sha256Hash); err != nil {
		u.logger.Error("同步 virus-database PluginConfig 失败", zap.Error(err))
		// 不阻断，组件记录已成功
	}

	return nil
}

// syncPluginConfig 将病毒库版本信息同步到 PluginConfig 表
func (u *VirusDBUpdater) syncPluginConfig(version, sha256Hash string) error {
	var pc model.PluginConfig
	err := u.db.Where("name = ?", virusDBComponentName).First(&pc).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return fmt.Errorf("query plugin_config: %w", err)
	}

	// 构造下载 URL（始终使用相对路径，由 AC 端根据 backend_url 动态拼接）
	downloadURL := "/api/v1/plugins/download/" + virusDBComponentName

	if err == gorm.ErrRecordNotFound {
		pc = model.PluginConfig{
			Name:         virusDBComponentName,
			Type:         model.PluginTypeVirusDB,
			Version:      version,
			SHA256:       sha256Hash,
			DownloadURLs: model.StringArray{downloadURL},
			RuntimeTypes: model.StringArray{"vm"},
			Enabled:      true,
			Description:  "ClamAV 病毒库（自动更新）",
		}
		return u.db.Create(&pc).Error
	}

	// 更新已有记录
	return u.db.Model(&pc).Updates(map[string]interface{}{
		"version":       version,
		"sha256":        sha256Hash,
		"download_urls": model.StringArray{downloadURL},
		"enabled":       true,
	}).Error
}

// fileSHA256 计算文件 SHA256 和大小
func (u *VirusDBUpdater) fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func (u *VirusDBUpdater) acquireLock(ctx context.Context) bool {
	if u.redisClient == nil {
		return true
	}
	result, err := u.redisClient.SetArgs(ctx, virusDBLockKey, managerInstanceID,
		redis.SetArgs{Mode: "NX", TTL: virusDBLockTTL}).Result()
	if err != nil {
		u.logger.Warn("获取病毒库更新锁失败，降级为无锁执行", zap.Error(err))
		return true
	}
	return result == "OK"
}

func (u *VirusDBUpdater) releaseLock(ctx context.Context) {
	if u.redisClient == nil {
		return
	}
	const script = `if redis.call("get",KEYS[1])==ARGV[1] then return redis.call("del",KEYS[1]) else return 0 end`
	if err := u.redisClient.Eval(ctx, script, []string{virusDBLockKey}, managerInstanceID).Err(); err != nil {
		u.logger.Warn("释放病毒库更新锁失败", zap.Error(err))
	}
}
