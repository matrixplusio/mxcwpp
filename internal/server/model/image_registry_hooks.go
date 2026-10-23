package model

import "gorm.io/gorm"

// SealSecret 按当前 KMS 配置加密一个凭证；未启用 KMS 时原样返回。
//
// 给 Updates(map) 这类不经模型钩子的写法用：钩子只改结构体字段，map 里的值会以明文落库。
func SealSecret(s string) (string, error) {
	if !kmsEnabled() || s == "" || isEncrypted(s) {
		return s, nil
	}
	return globalKMS.EncryptString(s)
}

// BeforeSave 仓库密码（或 GCP SA JSON）写库前加密。
func (r *ImageRegistry) BeforeSave(_ *gorm.DB) error {
	enc, err := SealSecret(r.Password)
	if err != nil {
		return err
	}
	r.Password = enc
	return nil
}

// AfterFind 读库后解密；没有加密前缀的历史明文照常可用。
func (r *ImageRegistry) AfterFind(_ *gorm.DB) error {
	if !kmsEnabled() || !isEncrypted(r.Password) {
		return nil
	}
	plain, err := globalKMS.DecryptString(r.Password)
	if err != nil {
		return err
	}
	r.Password = plain
	return nil
}
