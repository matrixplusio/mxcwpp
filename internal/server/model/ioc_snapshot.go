package model

import "time"

// IOCSnapshot stores a point-in-time export of threat intelligence IOC data.
// The Manager creates snapshots after each SyncIOCs() run, and the AgentCenter
// reads them to broadcast IOC updates to online agents.
type IOCSnapshot struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint      `gorm:"primarykey" json:"id"`
	Version   string    `gorm:"type:varchar(32);index" json:"version"`        // SHA256[:16] of full data
	Data      string    `gorm:"type:mediumtext" json:"-"`                     // Full IOC JSON: {"ip":[...], "hash":[...], "url":[...]}
	DiffAdded string    `gorm:"type:mediumtext" json:"-"`                     // Incremental additions since previous version (same JSON format)
	DiffRemov string    `gorm:"type:mediumtext;column:diff_removed" json:"-"` // Incremental removals since previous version
	PrevVer   string    `gorm:"type:varchar(32)" json:"prev_version"`         // Previous version for diff chain
	Count     int       `gorm:"default:0" json:"count"`                       // Total IOC count
	CreatedAt time.Time `json:"created_at"`
}

func (IOCSnapshot) TableName() string {
	return "ioc_snapshots"
}
