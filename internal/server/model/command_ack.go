package model

// CommandAckRecord 命令执行回包记录
type CommandAckRecord struct {
	ID             uint      `gorm:"primaryKey;column:id;autoIncrement" json:"id"`
	CommandID      string    `gorm:"column:command_id;type:varchar(64);uniqueIndex;not null" json:"command_id"`
	CommandType    string    `gorm:"column:command_type;type:varchar(50);not null" json:"command_type"`
	HostID         string    `gorm:"column:host_id;type:varchar(64);not null;index" json:"host_id"`
	Hostname       string    `gorm:"column:hostname;type:varchar(200)" json:"hostname"`
	Status         string    `gorm:"column:status;type:varchar(20);not null" json:"status"`
	ErrorCode      int32     `gorm:"column:error_code;type:int;default:0" json:"error_code"`
	ErrorMessage   string    `gorm:"column:error_message;type:text" json:"error_message,omitempty"`
	Output         string    `gorm:"column:output;type:text" json:"output,omitempty"`
	AcknowledgedAt LocalTime `gorm:"column:acknowledged_at;type:timestamp" json:"acknowledged_at"`
	CreatedAt      LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
}

// TableName 指定表名
func (CommandAckRecord) TableName() string {
	return "command_ack_records"
}
