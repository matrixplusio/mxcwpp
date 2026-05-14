// Package model 提供数据库模型定义
package model

// AssetUser 账户资产模型（注意：与 User 用户模型区分开）
type AssetUser struct {
	ID          string    `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID      string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	Username    string    `gorm:"column:username;type:varchar(100);not null" json:"username"`
	UID         string    `gorm:"column:uid;type:varchar(20);not null" json:"uid"`
	GID         string    `gorm:"column:gid;type:varchar(20)" json:"gid"`
	Groupname   string    `gorm:"column:groupname;type:varchar(100)" json:"groupname"`
	HomeDir     string    `gorm:"column:home_dir;type:varchar(255)" json:"home_dir"`
	Shell       string    `gorm:"column:shell;type:varchar(255)" json:"shell"`
	Comment     string    `gorm:"column:comment;type:varchar(255)" json:"comment"`
	HasPassword bool      `gorm:"column:has_password;type:boolean;default:false" json:"has_password"`
	CollectedAt LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (AssetUser) TableName() string {
	return "asset_users"
}
