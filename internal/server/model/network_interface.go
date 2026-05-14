// Package model 提供数据库模型定义
package model

// NetInterface 网络接口资产模型
type NetInterface struct {
	ID            string      `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID        string      `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	InterfaceName string      `gorm:"column:interface_name;type:varchar(50);not null" json:"interface_name"` // eth0、ens33 等
	MACAddress    string      `gorm:"column:mac_address;type:varchar(20)" json:"mac_address"`
	IPv4Addresses StringArray `gorm:"column:ipv4_addresses;type:text" json:"ipv4_addresses"` // JSON 数组
	IPv6Addresses StringArray `gorm:"column:ipv6_addresses;type:text" json:"ipv6_addresses"` // JSON 数组
	MTU           int         `gorm:"column:mtu;type:int" json:"mtu"`
	State         string      `gorm:"column:state;type:varchar(20)" json:"state"`                               // up、down
	BytesRecv     uint64      `gorm:"column:bytes_recv;type:bigint unsigned;default:0" json:"bytes_recv"`       // 累计接收字节数
	BytesSent     uint64      `gorm:"column:bytes_sent;type:bigint unsigned;default:0" json:"bytes_sent"`       // 累计发送字节数
	PacketsDrop   uint64      `gorm:"column:packets_drop;type:bigint unsigned;default:0" json:"packets_drop"`   // 接收丢包数
	PacketsError  uint64      `gorm:"column:packets_error;type:bigint unsigned;default:0" json:"packets_error"` // 接收错误数
	CollectedAt   LocalTime   `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (NetInterface) TableName() string {
	return "network_interfaces"
}
