package api

import (
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 插件灰度：指定版本只下发给指定主机。见 model.PluginCanary。

// signVersionPackages 给版本下每个启用的插件包分别签名并写回。插件配置只存一份（优先 amd64）的
// 哈希与签名，AgentCenter 下发时按主机架构换成对应包的；不逐包签名，非 amd64 主机拿到的签名
// 对不上自己那份包，插件会被拒绝加载。未配置签名器时把签名清空，与插件配置的行为一致。
func (h *ComponentsHandler) signVersionPackages(versionID uint) error {
	var pkgs []model.ComponentPackage
	if err := h.db.Where("version_id = ? AND enabled = ? AND pkg_type IN ?", versionID, true,
		[]model.PackageType{model.PackageTypeBinary, model.PackageTypeTGZ}).Find(&pkgs).Error; err != nil {
		return err
	}
	// 一个包失败不影响其余的包：能签的都签上，错误汇总返回。
	var errs []error
	for _, p := range pkgs {
		sig := ""
		if h.signer != nil && p.SHA256 != "" {
			var err error
			if sig, err = h.signer.SignSHA256(p.SHA256); err != nil {
				errs = append(errs, fmt.Errorf("签名 %s 包失败: %w", p.Arch, err))
				continue
			}
		}
		if p.Signature == sig {
			continue
		}
		if err := h.db.Model(&model.ComponentPackage{}).Where("id = ?", p.ID).Update("signature", sig).Error; err != nil {
			errs = append(errs, fmt.Errorf("保存 %s 包签名失败: %w", p.Arch, err))
		}
	}
	return errors.Join(errs...)
}

// backfillPackageSignatures 给插件配置与灰度正在使用的版本补签。逐包签名是后加的：
// 升级前上传的包都没有签名，不补的话启用了签名的平台上，非 amd64 主机一律加载失败。
// 签名不变的包不写库，多个 Manager 副本同时执行也安全。
func (h *ComponentsHandler) backfillPackageSignatures() {
	if h.signer == nil {
		return
	}
	type ref struct{ Name, Version string }
	var refs, canaries []ref
	if err := h.db.Model(&model.PluginConfig{}).Select("name, version").Scan(&refs).Error; err != nil {
		h.logger.Error("补签插件包：读取插件配置失败", zap.Error(err))
		return
	}
	// 灰度读不出来不影响全局配置用到的版本补签
	if err := h.db.Model(&model.PluginCanary{}).Select("plugin_name AS name, version").Scan(&canaries).Error; err != nil {
		h.logger.Error("补签插件包：读取插件灰度失败，只补签全局配置使用的版本", zap.Error(err))
		canaries = nil
	}
	signed := 0
	for _, r := range append(refs, canaries...) {
		if r.Name == "" || r.Version == "" {
			continue
		}
		_, ver, err := h.pluginVersion(r.Name, r.Version)
		if err != nil {
			continue
		}
		if err := h.signVersionPackages(ver.ID); err != nil {
			h.logger.Error("补签插件包失败，非 amd64 主机可能无法加载该版本",
				zap.String("plugin", r.Name), zap.String("version", r.Version), zap.Error(err))
			continue
		}
		signed++
	}
	h.logger.Info("插件包签名补签完成", zap.Int("versions", signed))
}

// pluginPackageFor 取版本的包（优先 amd64）。全局插件配置与灰度用同一个取法，sha256 才对得上。
func (h *ComponentsHandler) pluginPackageFor(versionID uint) (model.ComponentPackage, error) {
	var pkg model.ComponentPackage
	if err := h.db.Where("version_id = ? AND arch = ? AND enabled = ?", versionID, "amd64", true).First(&pkg).Error; err == nil {
		return pkg, nil
	}
	err := h.db.Where("version_id = ? AND enabled = ?", versionID, true).First(&pkg).Error
	return pkg, err
}

type pluginCanaryReq struct {
	Version string   `json:"version" binding:"required"`
	HostIDs []string `json:"host_ids" binding:"required,min=1"`
}

// pluginVersion 按插件名与版本号查版本。
func (h *ComponentsHandler) pluginVersion(name, version string) (model.Component, model.ComponentVersion, error) {
	var comp model.Component
	if err := h.db.Where("name = ? AND category = ?", name, model.ComponentCategoryPlugin).First(&comp).Error; err != nil {
		return comp, model.ComponentVersion{}, fmt.Errorf("插件 %s 不存在", name)
	}
	var ver model.ComponentVersion
	if err := h.db.Where("component_id = ? AND version = ?", comp.ID, version).First(&ver).Error; err != nil {
		return comp, ver, fmt.Errorf("插件 %s 没有版本 %s", name, version)
	}
	return comp, ver, nil
}

// resend 让 AC 给这些主机重发插件配置；未注入重发器时在 agent 下次重连生效。
func (h *ComponentsHandler) resend(hostIDs []string) (int, string) {
	if h.resender == nil || len(hostIDs) == 0 {
		return 0, "agent 下次重连时生效"
	}
	n, err := h.resender.ResendPluginConfigs(hostIDs)
	if err != nil {
		h.logger.Warn("重发插件配置部分失败", zap.Int("sent", n), zap.Error(err))
		return n, "部分 AC 重发失败，其余主机在下次重连时生效"
	}
	return n, "已立即下发"
}

// GetPluginCanary 查看插件当前灰度
// GET /api/v1/components/plugins/:name/canary
func (h *ComponentsHandler) GetPluginCanary(c *gin.Context) {
	var canary model.PluginCanary
	err := h.db.Where("plugin_name = ?", c.Param("name")).First(&canary).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		Success(c, nil)
		return
	}
	if err != nil {
		InternalError(c, "查询灰度失败")
		return
	}
	Success(c, canary)
}

// StartPluginCanary 开始（或扩大）插件灰度
// POST /api/v1/components/plugins/:name/canary {version, host_ids}
//
// 同一版本再次提交即追加主机；已有其它版本的灰度时拒绝，先回滚或转正——
// 两个版本同时在灰度，出了问题分不清是哪一个。
func (h *ComponentsHandler) StartPluginCanary(c *gin.Context) {
	name := c.Param("name")
	var req pluginCanaryReq
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "需要 version 与 host_ids")
		return
	}
	_, ver, err := h.pluginVersion(name, req.Version)
	if err != nil {
		NotFound(c, err.Error())
		return
	}
	var global model.PluginConfig
	globalErr := h.db.Where("name = ?", name).First(&global).Error
	if globalErr == nil && global.Version == req.Version {
		BadRequest(c, "该版本已是全局版本，无需灰度")
		return
	}
	if globalErr != nil && !errors.Is(globalErr, gorm.ErrRecordNotFound) {
		InternalError(c, "查询插件配置失败")
		return
	}
	pkg, err := h.pluginPackageFor(ver.ID)
	if err != nil || pkg.SHA256 == "" {
		BadRequest(c, "该版本没有可用的包，先上传")
		return
	}
	var known int64
	h.db.Model(&model.Host{}).Where("host_id IN ?", req.HostIDs).Count(&known)
	if int(known) != len(uniqueStrings(req.HostIDs)) {
		BadRequest(c, "host_ids 中有不存在的主机")
		return
	}
	sig := ""
	if h.signer != nil {
		if sig, err = h.signer.SignSHA256(pkg.SHA256); err != nil {
			InternalError(c, "插件签名失败")
			return
		}
	}
	if err := h.signVersionPackages(ver.ID); err != nil {
		h.logger.Error("灰度版本逐包签名失败", zap.String("plugin", name), zap.String("version", req.Version), zap.Error(err))
		InternalError(c, "插件签名失败")
		return
	}

	// 全新插件还没有全局配置，而 AC 只给已有的全局配置换灰度版本——不先有一条，灰度什么也不下发。
	// 占位配置不带下载地址：AC 对没有下载地址的配置一律跳过，于是只有灰度名单里的主机拿得到插件；
	// 转正时由正式配置（带下载地址）覆盖它。
	if errors.Is(globalErr, gorm.ErrRecordNotFound) {
		placeholder := model.PluginConfig{Name: name, Type: model.PluginType(name), DownloadURLs: model.StringArray{},
			RuntimeTypes: runtimeTypesForPlugin(name), Enabled: true,
			Description: "灰度占位：只下发给灰度名单里的主机，转正后由正式配置覆盖"}
		if err := h.db.Where("name = ?", name).FirstOrCreate(&placeholder).Error; err != nil {
			h.logger.Error("创建灰度占位配置失败", zap.Error(err))
			InternalError(c, "保存灰度失败")
			return
		}
	}

	var canary model.PluginCanary
	err = h.db.Where("plugin_name = ?", name).First(&canary).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		canary = model.PluginCanary{PluginName: name, Version: req.Version, SHA256: pkg.SHA256, Signature: sig,
			HostIDs: model.StringArray(uniqueStrings(req.HostIDs)), CreatedBy: h.getCurrentUser(c)}
		err = h.db.Create(&canary).Error
	case err != nil:
	case canary.Version != req.Version:
		Conflict(c, fmt.Sprintf("插件 %s 正在灰度版本 %s，先回滚或转正", name, canary.Version))
		return
	default:
		canary.HostIDs = model.StringArray(uniqueStrings(append([]string(canary.HostIDs), req.HostIDs...)))
		err = h.db.Model(&canary).Update("host_ids", canary.HostIDs).Error
	}
	if err != nil {
		h.logger.Error("保存插件灰度失败", zap.Error(err))
		InternalError(c, "保存灰度失败")
		return
	}

	sent, msg := h.resend(req.HostIDs)
	h.logger.Info("插件灰度", zap.String("plugin", name), zap.String("version", req.Version),
		zap.Int("hosts", len(canary.HostIDs)), zap.Int("resent", sent))
	Success(c, gin.H{"canary": canary, "resent": sent, "message": msg})
}

// RollbackPluginCanary 结束灰度，灰度主机回到全局版本
// DELETE /api/v1/components/plugins/:name/canary
func (h *ComponentsHandler) RollbackPluginCanary(c *gin.Context) {
	var canary model.PluginCanary
	if err := h.db.Where("plugin_name = ?", c.Param("name")).First(&canary).Error; err != nil {
		NotFound(c, "该插件没有进行中的灰度")
		return
	}
	if err := h.db.Delete(&canary).Error; err != nil {
		InternalError(c, "删除灰度失败")
		return
	}
	sent, msg := h.resend(canary.HostIDs)
	Success(c, gin.H{"rolled_back": canary.HostIDs, "resent": sent, "message": msg})
}

// PromotePluginCanary 灰度转正：灰度版本设为最新版本（全局），删除灰度记录。
// POST /api/v1/components/plugins/:name/canary/promote
//
// 只改全局配置，不广播：其余主机在下次重连时升级；要立即全量，再调 /components/plugins/broadcast。
func (h *ComponentsHandler) PromotePluginCanary(c *gin.Context) {
	name := c.Param("name")
	var canary model.PluginCanary
	if err := h.db.Where("plugin_name = ?", name).First(&canary).Error; err != nil {
		NotFound(c, "该插件没有进行中的灰度")
		return
	}
	_, ver, err := h.pluginVersion(name, canary.Version)
	if err != nil {
		NotFound(c, err.Error())
		return
	}
	if err := h.applyLatestVersion(&ver); err != nil {
		h.logger.Error("灰度转正失败", zap.Error(err))
		InternalError(c, "转正失败")
		return
	}
	if err := h.db.Delete(&canary).Error; err != nil {
		InternalError(c, "已设为最新版本，但删除灰度记录失败")
		return
	}
	Success(c, gin.H{"version": canary.Version,
		"message": "已设为全局版本；其余主机下次重连时升级，要立即全量请调用插件广播"})
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
