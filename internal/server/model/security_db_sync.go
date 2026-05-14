package model

import "time"

// SecurityDBSyncRecord 安全库同步记录（病毒库、YARA 规则库等）
type SecurityDBSyncRecord struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	DBType    string    `json:"dbType" gorm:"type:varchar(32);not null;index;comment:库类型(clamav/yara-rules)"`
	Version   string    `json:"version" gorm:"type:varchar(64);comment:版本号"`
	Status    string    `json:"status" gorm:"type:varchar(16);not null;index;comment:状态(running/success/failed)"`
	FileSize  int64     `json:"fileSize" gorm:"comment:包大小(字节)"`
	SHA256    string    `json:"sha256" gorm:"type:varchar(64);comment:校验和"`
	ErrorMsg  string    `json:"errorMsg" gorm:"type:text;comment:失败原因"`
	Duration  int       `json:"duration" gorm:"comment:耗时(秒)"`
	StartedAt time.Time `json:"startedAt" gorm:"not null;comment:开始时间"`
	CreatedAt LocalTime `json:"createdAt" gorm:"autoCreateTime"`
}
