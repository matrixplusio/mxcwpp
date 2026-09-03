package model

// HostLoginProfileState persists the abnormal-login detector's per-host profile
// so an engine restart does not reset every host to an empty profile.
//
// 画像丢失不只是丢历史：画像为空时每台主机的第一次登录都会同时命中新国家 +
// 新 IP 段 + 新用户，学习期也会从零重新计时。四个维度都是 map，按 JSON 文本存，
// 避免每维一张关联表（口径同 host_baseline_states）。
type HostLoginProfileState struct {
	TenantID  string    `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID        uint      `gorm:"primarykey" json:"id"`
	HostID    string    `gorm:"type:varchar(64);uniqueIndex" json:"host_id"`
	Samples   int       `json:"samples"`    // 已观测的登录次数（学习期毕业条件之一）
	FirstSeen LocalTime `json:"first_seen"` // 该主机首次登录时间（学习期起点）

	CountriesJSON string `gorm:"type:text" json:"-"` // JSON map[country]hits
	HoursJSON     string `gorm:"type:text" json:"-"` // JSON map[hour 0-23]hits
	UsersJSON     string `gorm:"type:text" json:"-"` // JSON map[username]lastSeen
	IPNetsJSON    string `gorm:"type:text" json:"-"` // JSON map["a.b.c.0/24"]lastSeen

	CreatedAt LocalTime `json:"created_at"`
	UpdatedAt LocalTime `json:"updated_at"`
}

func (HostLoginProfileState) TableName() string { return "host_login_profile_states" }
