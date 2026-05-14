// Package model 提供数据库模型定义
package model

// UserRole 用户角色
type UserRole string

const (
	UserRoleAdmin UserRole = "admin"
	UserRoleUser  UserRole = "user"
)

// UserStatus 用户状态
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
)

// User 用户模型
type User struct {
	ID                  uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	Username            string     `gorm:"column:username;type:varchar(64);uniqueIndex;not null" json:"username"`
	Password            string     `gorm:"column:password;type:varchar(255);not null" json:"-"` // 密码不返回给前端
	Email               string     `gorm:"column:email;type:varchar(255)" json:"email"`
	Role                UserRole   `gorm:"column:role;type:varchar(20);default:'user'" json:"role"`
	Status              UserStatus `gorm:"column:status;type:varchar(20);default:'active'" json:"status"`
	ForceChangePassword bool       `gorm:"column:force_change_password;type:tinyint(1);default:0" json:"force_change_password"`
	LoginFailCount      int        `gorm:"column:login_fail_count;type:int;default:0" json:"-"`
	LockedUntil         *LocalTime `gorm:"column:locked_until;type:timestamp" json:"-"`
	LastLogin           *LocalTime `gorm:"column:last_login;type:timestamp" json:"last_login"`
	CreatedAt           LocalTime  `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt           LocalTime  `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" json:"updated_at"`
}

// TableName 指定表名
func (User) TableName() string {
	return "users"
}
