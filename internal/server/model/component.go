// Package model 提供数据库模型定义
package model

import (
	"gorm.io/gorm"
)

// ComponentType 组件类型
type ComponentType string

const (
	ComponentTypeAgent       ComponentType = "agent"          // Agent 主程序
	ComponentTypeBaseline    ComponentType = "baseline"       // 基线检查插件
	ComponentTypeCollector   ComponentType = "collector"      // 资产采集插件
	ComponentTypeFIM         ComponentType = "fim"            // 文件完整性监控插件
	ComponentTypeScanner     ComponentType = "scanner"        // 病毒查杀插件
	ComponentTypeRemediation ComponentType = "remediation"    // 漏洞修复插件
	ComponentTypeVirusDB     ComponentType = "virus-database" // ClamAV 病毒库
	ComponentTypeMLModel     ComponentType = "ml-model"       // 本地 ML 模型 (ONNX/TFLite, Sprint 4 PR68)
	ComponentTypeYARARules   ComponentType = "yara-rules"     // YARA 规则包 (后续 Sprint)
)

// ComponentCategory 组件分类
type ComponentCategory string

const (
	ComponentCategoryAgent      ComponentCategory = "agent"      // Agent 主程序
	ComponentCategoryPlugin     ComponentCategory = "plugin"     // 插件
	ComponentCategoryDependency ComponentCategory = "dependency" // 第三方依赖
)

// PackageType 包格式类型
type PackageType string

const (
	PackageTypeRPM    PackageType = "rpm"    // RPM 包 (RHEL/CentOS/Rocky)
	PackageTypeDEB    PackageType = "deb"    // DEB 包 (Debian/Ubuntu)
	PackageTypeBinary PackageType = "binary" // 二进制文件
	PackageTypeTGZ    PackageType = "tgz"    // tar.gz 包（第三方依赖）
)

// Component 组件表
// 存储组件的基本信息（agent、baseline、collector 等）
type Component struct {
	TenantID    string            `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint              `gorm:"primaryKey" json:"id"`
	Name        string            `gorm:"size:32;not null;uniqueIndex:idx_component_name" json:"name"` // 组件名称 (agent, baseline, collector)
	Category    ComponentCategory `gorm:"size:16;not null" json:"category"`                            // 组件分类 (agent, plugin)
	Description string            `gorm:"size:512" json:"description"`                                 // 组件描述
	CreatedBy   string            `gorm:"size:64" json:"created_by"`                                   // 创建者
	CreatedAt   LocalTime         `json:"created_at"`                                                  // 创建时间
	UpdatedAt   LocalTime         `json:"updated_at"`                                                  // 更新时间
	DeletedAt   gorm.DeletedAt    `gorm:"index" json:"-"`                                              // 软删除

	// 关联
	Versions []ComponentVersion `gorm:"foreignKey:ComponentID" json:"versions,omitempty"`
}

// TableName 返回表名
func (Component) TableName() string {
	return "components"
}

// ComponentVersion 组件版本表
// 存储组件的版本信息
type ComponentVersion struct {
	TenantID    string         `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint           `gorm:"primaryKey" json:"id"`
	ComponentID uint           `gorm:"not null;index:idx_version_component" json:"component_id"`               // 关联的组件 ID
	Version     string         `gorm:"size:32;not null;index:idx_version_component,priority:2" json:"version"` // 版本号 (1.0.0, 1.8.5.31)
	Changelog   string         `gorm:"type:text" json:"changelog"`                                             // 更新日志
	IsLatest    bool           `gorm:"default:false;index:idx_version_latest" json:"is_latest"`                // 是否是最新版本
	CreatedBy   string         `gorm:"size:64" json:"created_by"`                                              // 创建者/上传者
	CreatedAt   LocalTime      `json:"created_at"`                                                             // 创建时间
	UpdatedAt   LocalTime      `json:"updated_at"`                                                             // 更新时间
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`                                                         // 软删除

	// 关联
	Component *Component         `gorm:"foreignKey:ComponentID" json:"component,omitempty"`
	Packages  []ComponentPackage `gorm:"foreignKey:VersionID" json:"packages,omitempty"`
}

// TableName 返回表名
func (ComponentVersion) TableName() string {
	return "component_versions"
}

// ComponentPackage 组件包表
// 存储组件版本的具体文件（不同平台、架构）
type ComponentPackage struct {
	TenantID   string         `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID         uint           `gorm:"primaryKey" json:"id"`
	VersionID  uint           `gorm:"not null;uniqueIndex:idx_unique_package" json:"version_id"`       // 关联的版本 ID
	OS         string         `gorm:"size:32;not null;default:linux" json:"os"`                        // 操作系统 (linux)
	Arch       string         `gorm:"size:32;not null;uniqueIndex:idx_unique_package" json:"arch"`     // 架构 (amd64, arm64)
	PkgType    PackageType    `gorm:"size:16;not null;uniqueIndex:idx_unique_package" json:"pkg_type"` // 包类型 (rpm, deb, binary)
	FilePath   string         `gorm:"size:512;not null" json:"file_path"`                              // 文件存储路径
	FileName   string         `gorm:"size:256;not null" json:"file_name"`                              // 原始文件名
	FileSize   int64          `gorm:"not null" json:"file_size"`                                       // 文件大小 (字节)
	SHA256     string         `gorm:"size:64" json:"sha256"`                                           // SHA256 校验和
	Enabled    bool           `gorm:"default:true" json:"enabled"`                                     // 是否启用
	UploadedBy string         `gorm:"size:64" json:"uploaded_by"`                                      // 上传用户
	UploadedAt LocalTime      `json:"uploaded_at"`                                                     // 上传时间
	DeletedAt  gorm.DeletedAt `gorm:"uniqueIndex:idx_unique_package" json:"-"`                         // 软删除（包含在唯一索引中，支持软删除后重新上传）

	// 关联
	Version *ComponentVersion `gorm:"foreignKey:VersionID" json:"version,omitempty"`
}

// TableName 返回表名
func (ComponentPackage) TableName() string {
	return "component_packages"
}

// ComponentWithLatestVersion 组件及其最新版本信息（用于列表展示）
type ComponentWithLatestVersion struct {
	Component
	LatestVersion string `json:"latest_version"` // 最新版本号
	VersionCount  int64  `json:"version_count"`  // 版本数量
	PackageCount  int64  `json:"package_count"`  // 包数量
}

// VersionWithPackages 版本及其包信息（用于详情展示）
type VersionWithPackages struct {
	ComponentVersion
	PackagesSummary []PackageSummary `json:"packages_summary"` // 包摘要列表
}

// PackageSummary 包摘要信息
type PackageSummary struct {
	Arch     string `json:"arch"`
	PkgType  string `json:"pkg_type"`
	FileSize int64  `json:"file_size"`
	Uploaded bool   `json:"uploaded"`
}
