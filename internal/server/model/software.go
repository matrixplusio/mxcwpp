// Package model 提供数据库模型定义
package model

// Software 软件包资产模型
type Software struct {
	ID           string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID       string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	Name         string    `gorm:"column:name;type:varchar(255);not null" json:"name"`
	Version      string    `gorm:"column:version;type:varchar(100)" json:"version"`
	Architecture string    `gorm:"column:architecture;type:varchar(50)" json:"architecture"`
	PackageType  string    `gorm:"column:package_type;type:varchar(50);not null" json:"package_type"` // rpm、deb、pip、npm、jar 等
	Vendor       string    `gorm:"column:vendor;type:varchar(255)" json:"vendor"`
	InstallTime  string    `gorm:"column:install_time;type:varchar(50)" json:"install_time"`
	PURL         string    `gorm:"column:purl;type:varchar(500);index" json:"purl"`
	CollectedAt  LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Software) TableName() string {
	return "software"
}
