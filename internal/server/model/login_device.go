package model

// LoginDevice 记录某用户在某设备上的成功登录情况，用于登录风控（可信设备判定）。
//
// 设备 ID 由浏览器本地生成并持久化（localStorage），每次登录上报。
// 同一 (username, device_id) 成功登录次数达到阈值且仍在有效期内即视为"可信设备"，
// 可信设备登录免图形验证码；新设备/不常用设备在连续失败后才要求验证码。
type LoginDevice struct {
	ID            uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	Username      string     `gorm:"column:username;type:varchar(64);not null;index:idx_user_device,unique" json:"username"`
	DeviceID      string     `gorm:"column:device_id;type:varchar(64);not null;index:idx_user_device,unique" json:"device_id"`
	SuccessCount  int        `gorm:"column:success_count;type:int;default:0" json:"success_count"`
	LastSuccessAt *LocalTime `gorm:"column:last_success_at;type:timestamp" json:"last_success_at"`
	CreatedAt     LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName 指定表名
func (LoginDevice) TableName() string { return "login_devices" }
