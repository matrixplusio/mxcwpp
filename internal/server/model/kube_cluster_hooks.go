package model

import (
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kms"
)

// KMSProvider 接口避免 model 包硬依赖 KMS 实例 (启动时注入)。
type KMSProvider interface {
	EncryptString(s string) (string, error)
	DecryptString(s string) (string, error)
}

var globalKMS KMSProvider

// SetKMS 注入 KMS (manager 启动时调用)。
//
// 不注入时 KubeConfig / GCPCredentialsJSON 仍走明文 (兼容现有部署),
// 但 manager 启动会 logger.Warn 提醒。
func SetKMS(k KMSProvider) { globalKMS = k }

// kmsEnabled 是否启用 KMS 加密。
func kmsEnabled() bool { return globalKMS != nil }

// BeforeSave gorm hook: 写库前加密敏感字段。
//
// 已加密 (kms:v1: 前缀) 的字段不重复加密 (Update 部分场景)。
func (c *KubeCluster) BeforeSave(_ *gorm.DB) error {
	if !kmsEnabled() {
		return nil
	}
	if c.KubeConfig != "" && !isEncrypted(c.KubeConfig) {
		enc, err := globalKMS.EncryptString(c.KubeConfig)
		if err != nil {
			return err
		}
		c.KubeConfig = enc
	}
	if c.GCPCredentialsJSON != "" && !isEncrypted(c.GCPCredentialsJSON) {
		enc, err := globalKMS.EncryptString(c.GCPCredentialsJSON)
		if err != nil {
			return err
		}
		c.GCPCredentialsJSON = enc
	}
	return nil
}

// AfterFind gorm hook: 读库后解密。
func (c *KubeCluster) AfterFind(_ *gorm.DB) error {
	if !kmsEnabled() {
		return nil
	}
	if isEncrypted(c.KubeConfig) {
		plain, err := globalKMS.DecryptString(c.KubeConfig)
		if err != nil {
			return err
		}
		c.KubeConfig = plain
	}
	if isEncrypted(c.GCPCredentialsJSON) {
		plain, err := globalKMS.DecryptString(c.GCPCredentialsJSON)
		if err != nil {
			return err
		}
		c.GCPCredentialsJSON = plain
	}
	return nil
}

func isEncrypted(s string) bool {
	return len(s) > 7 && s[:7] == "kms:v1:"
}

// 编译期类型守卫: KMS 实现满足 KMSProvider。
var _ KMSProvider = (*kms.KMS)(nil)
