package api

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/common/signing"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// TestSignVersionPackages_EachArch 版本下每个架构的包各自签名：AgentCenter 按主机架构下发时，
// 每台主机拿到的签名都要对得上它自己那份包的哈希。
func TestSignVersionPackages_EachArch(t *testing.T) {
	db := setupTestDB(t)
	pub, priv, err := signing.GenerateKeyPair()
	require.NoError(t, err)
	signer, err := signing.NewSigner(priv)
	require.NoError(t, err)

	comp := model.Component{Name: "fim", Category: model.ComponentCategoryPlugin}
	require.NoError(t, db.Create(&comp).Error)
	ver := model.ComponentVersion{ComponentID: comp.ID, Version: "1.0.1", IsLatest: true}
	require.NoError(t, db.Create(&ver).Error)
	shas := map[string]string{
		"amd64": "1111111111111111111111111111111111111111111111111111111111111111",
		"arm64": "2222222222222222222222222222222222222222222222222222222222222222",
	}
	for arch, sha := range shas {
		require.NoError(t, db.Create(&model.ComponentPackage{VersionID: ver.ID, Arch: arch, PkgType: model.PackageTypeBinary,
			FilePath: "/tmp/fim-" + arch, FileName: "fim-" + arch, SHA256: sha, Enabled: true}).Error)
	}

	h := &ComponentsHandler{db: db, logger: zap.NewNop(), signer: signer}
	require.NoError(t, h.signVersionPackages(ver.ID))

	var pkgs []model.ComponentPackage
	require.NoError(t, db.Where("version_id = ?", ver.ID).Find(&pkgs).Error)
	require.Len(t, pkgs, 2)
	for _, p := range pkgs {
		require.NotEmpty(t, p.Signature, "%s 包没有签名", p.Arch)
		require.NoError(t, signing.VerifySHA256(pub, shas[p.Arch], p.Signature), "%s 包的签名对不上自己的哈希", p.Arch)
	}

	// 未配置签名器：签名清空，与插件配置的行为一致
	h.signer = nil
	require.NoError(t, h.signVersionPackages(ver.ID))
	require.NoError(t, db.Where("version_id = ?", ver.ID).Find(&pkgs).Error)
	for _, p := range pkgs {
		require.Empty(t, p.Signature, "%s 包的签名应被清空", p.Arch)
	}
}

// TestSignVersionPackages_SkipsDisabledAndNonPlugin 停用的包与 rpm / deb 包不签名。
func TestSignVersionPackages_SkipsDisabledAndNonPlugin(t *testing.T) {
	db := setupTestDB(t)
	_, priv, err := signing.GenerateKeyPair()
	require.NoError(t, err)
	signer, err := signing.NewSigner(priv)
	require.NoError(t, err)
	comp := model.Component{Name: "fim", Category: model.ComponentCategoryPlugin}
	require.NoError(t, db.Create(&comp).Error)
	ver := model.ComponentVersion{ComponentID: comp.ID, Version: "1.0.1"}
	require.NoError(t, db.Create(&ver).Error)
	sha := "3333333333333333333333333333333333333333333333333333333333333333"
	disabled := model.ComponentPackage{VersionID: ver.ID, Arch: "arm64", PkgType: model.PackageTypeBinary, FilePath: "/tmp/a", FileName: "a", SHA256: sha, Enabled: true}
	require.NoError(t, db.Create(&disabled).Error)
	require.NoError(t, db.Model(&disabled).Update("enabled", false).Error)
	rpm := model.ComponentPackage{VersionID: ver.ID, Arch: "amd64", PkgType: model.PackageTypeRPM, FilePath: "/tmp/b", FileName: "b", SHA256: sha, Enabled: true}
	require.NoError(t, db.Create(&rpm).Error)

	h := &ComponentsHandler{db: db, logger: zap.NewNop(), signer: signer}
	require.NoError(t, h.signVersionPackages(ver.ID))
	var pkgs []model.ComponentPackage
	require.NoError(t, db.Where("version_id = ?", ver.ID).Find(&pkgs).Error)
	for _, p := range pkgs {
		require.Empty(t, p.Signature, "%s/%s 不应被签名", p.Arch, p.PkgType)
	}
}

// TestBackfillPackageSignatures 启动补签：插件配置正在使用的版本，升级前上传、没有签名的包被补上签名。
func TestBackfillPackageSignatures(t *testing.T) {
	db := setupTestDB(t)
	pub, priv, err := signing.GenerateKeyPair()
	require.NoError(t, err)
	signer, err := signing.NewSigner(priv)
	require.NoError(t, err)
	comp := model.Component{Name: "fim", Category: model.ComponentCategoryPlugin}
	require.NoError(t, db.Create(&comp).Error)
	ver := model.ComponentVersion{ComponentID: comp.ID, Version: "1.0.1", IsLatest: true}
	require.NoError(t, db.Create(&ver).Error)
	sha := "4444444444444444444444444444444444444444444444444444444444444444"
	require.NoError(t, db.Create(&model.ComponentPackage{VersionID: ver.ID, Arch: "arm64", PkgType: model.PackageTypeBinary,
		FilePath: "/tmp/c", FileName: "c", SHA256: sha, Enabled: true}).Error)
	require.NoError(t, db.Create(&model.PluginConfig{Name: "fim", Type: "fim", Version: "1.0.1", SHA256: sha, Enabled: true}).Error)

	h := &ComponentsHandler{db: db, logger: zap.NewNop(), signer: signer}
	h.backfillPackageSignatures()
	var pkg model.ComponentPackage
	require.NoError(t, db.Where("version_id = ? AND arch = ?", ver.ID, "arm64").First(&pkg).Error)
	require.NoError(t, signing.VerifySHA256(pub, sha, pkg.Signature))
}
