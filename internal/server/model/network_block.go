package model

// NetworkBlockRule 网络阻断规则
// 通过 AC 下发 iptables/nftables 命令到 Agent 执行
type NetworkBlockRule struct {
	TenantID    string     `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID          uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	HostID      string     `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	IP          string     `gorm:"column:ip;type:varchar(45);not null" json:"ip"` // 被阻断的 IP (IPv4/IPv6)
	Port        int        `gorm:"column:port;default:0" json:"port"`             // 端口 (0 表示所有端口)
	Protocol    string     `gorm:"column:protocol;type:varchar(10);default:'tcp'" json:"protocol"`
	Direction   string     `gorm:"column:direction;type:varchar(20);default:'outbound'" json:"direction"` // inbound/outbound
	Reason      string     `gorm:"column:reason;type:varchar(500)" json:"reason"`
	Source      string     `gorm:"column:source;type:varchar(50);default:'manual'" json:"source"`  // manual/auto_response/threat_intel
	Status      string     `gorm:"column:status;type:varchar(20);default:'pending'" json:"status"` // pending/active/removed/failed
	CreatedBy   string     `gorm:"column:created_by;type:varchar(100)" json:"created_by"`
	CreatedAt   LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updated_at"`
	ActivatedAt *LocalTime `gorm:"column:activated_at;type:timestamp;null" json:"activated_at,omitempty"`
	RemovedAt   *LocalTime `gorm:"column:removed_at;type:timestamp;null" json:"removed_at,omitempty"`
}

func (NetworkBlockRule) TableName() string {
	return "network_block_rules"
}
