// Package model 提供数据库模型定义
// 本文件导出所有模型，方便统一导入
package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JSONValue 通用 JSON 序列化为 driver.Value（用于 GORM 自定义类型的 Value 方法）
func JSONValue(v any) (driver.Value, error) {
	return json.Marshal(v)
}

// JSONScan 通用 JSON 反序列化（用于 GORM 自定义类型的 Scan 方法）
func JSONScan(dest any, value any) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, dest)
}

// TimeFormat 统一的时间格式，不带时区
const TimeFormat = "2006-01-02 15:04:05"

// LocalTime 自定义时间类型，JSON 序列化时使用易读格式
type LocalTime time.Time

// MarshalJSON 实现 json.Marshaler 接口
func (t LocalTime) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil
	}
	return []byte(fmt.Sprintf("\"%s\"", tt.Format(TimeFormat))), nil
}

// UnmarshalJSON 实现 json.Unmarshaler 接口
func (t *LocalTime) UnmarshalJSON(data []byte) error {
	str := strings.Trim(string(data), "\"")
	if str == "null" || str == "" {
		return nil
	}
	// 尝试多种格式解析
	formats := []string{
		TimeFormat,
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05",
	}
	var err error
	for _, format := range formats {
		var parsed time.Time
		parsed, err = time.Parse(format, str)
		if err == nil {
			*t = LocalTime(parsed)
			return nil
		}
	}
	return fmt.Errorf("无法解析时间: %s", str)
}

// Value 实现 driver.Valuer 接口，用于数据库存储
func (t LocalTime) Value() (driver.Value, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return nil, nil
	}
	return tt, nil
}

// Scan 实现 sql.Scanner 接口，用于数据库读取
func (t *LocalTime) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		*t = LocalTime(v)
		return nil
	case []byte:
		parsed, err := time.Parse("2006-01-02 15:04:05", string(v))
		if err != nil {
			parsed, err = time.Parse(time.RFC3339, string(v))
		}
		if err != nil {
			return err
		}
		*t = LocalTime(parsed)
		return nil
	case string:
		parsed, err := time.Parse("2006-01-02 15:04:05", v)
		if err != nil {
			parsed, err = time.Parse(time.RFC3339, v)
		}
		if err != nil {
			return err
		}
		*t = LocalTime(parsed)
		return nil
	default:
		return fmt.Errorf("无法扫描类型 %T 到 LocalTime", value)
	}
}

// Time 返回底层的 time.Time 类型
func (t LocalTime) Time() time.Time {
	return time.Time(t)
}

// IsZero 检查时间是否为零值
func (t LocalTime) IsZero() bool {
	return time.Time(t).IsZero()
}

// String 返回格式化的时间字符串
func (t LocalTime) String() string {
	return time.Time(t).Format(TimeFormat)
}

// After 判断时间 t 是否在 u 之后
func (t LocalTime) After(u LocalTime) bool {
	return time.Time(t).After(time.Time(u))
}

// Before 判断时间 t 是否在 u 之前
func (t LocalTime) Before(u LocalTime) bool {
	return time.Time(t).Before(time.Time(u))
}

// Now 返回当前时间的 LocalTime
func Now() LocalTime {
	return LocalTime(time.Now())
}

// ToLocalTime 将 time.Time 转换为 LocalTime
func ToLocalTime(t time.Time) LocalTime {
	return LocalTime(t)
}

// ToLocalTimePtr 将 *time.Time 转换为 *LocalTime
func ToLocalTimePtr(t *time.Time) *LocalTime {
	if t == nil {
		return nil
	}
	lt := LocalTime(*t)
	return &lt
}

// 导出所有模型类型
var (
	// 所有模型列表，用于数据库迁移
	AllModels = []interface{}{
		&Host{},
		&PolicyGroup{},
		&Policy{},
		&Rule{},
		&ScanResult{},
		&ScanTask{},
		&TaskHostStatus{},
		&FixTask{},
		&FixResult{},
		&FixTaskHostStatus{},
		&User{},
		&Process{},
		&Port{},
		&AssetUser{},
		&Software{},
		&Container{},
		&App{},
		&NetInterface{},
		&Volume{},
		&Kmod{},
		&Service{},
		&Cron{},
		&HostMetric{},
		&HostMetricHourly{},
		&BusinessLine{},
		&SystemConfig{},
		&Notification{},
		&Alert{},
		&AlertWhitelist{},
		&AuditLog{},
		&PluginConfig{},
		&Component{},
		&ComponentVersion{},
		&ComponentPackage{},
		&HostPlugin{},
		&ComponentPushRecord{},
		&AgentRestartRecord{},
		&FIMPolicy{},
		&FIMEvent{},
		&FIMTask{},
		&FIMTaskHostStatus{},
		&FIMBaseline{},
		&FIMBaselineEntry{},
		&KubeCluster{},
		&KubeAlarm{},
		&KubeEvent{},
		&KubeBaseline{},
		&KubeBaselineTask{},
		&KubeBaselineRule{},
		&KubeExpressionTemplate{},
		&KubeWhitelist{},
		&KubeBaselineAlert{},
		&ConfigBackup{},
		&Vulnerability{},
		&AdvisoryPackage{},
		&HostVulnerability{},
		&CommandAckRecord{},
		&AntivirusScanTask{},
		&AntivirusScanResult{},
		&QuarantineFile{},
		&DetectionRule{},
		&NetworkBlockRule{},
		&SecurityDBSyncRecord{},
		&GeneratedReport{},
		&FeatureFlag{},
		&ConfigChangeRequest{},
		&UsageMetering{},
		&MonthlyBill{},
		&HoneypotPolicy{},
		&HoneypotDeploymentRecord{},
		&RootkitFinding{},
		&ADAuditEvent{},
		&ADAuditAlert{},
		&MLModelSpec{},
		&MLModelSubscription{},
		&MLModelDeploymentStatus{},
		&RetentionPolicy{},
		&MigrationJob{},
		&ComponentPushHost{},
		&RemediationTask{},
		&RemediationTaskEvent{},
		&VulnDataSource{},
		&ScanSchedule{},
		&ScanScheduleExecution{},
		&VulnCache{},
		&VulnDBImport{},
		&VulnScanTask{},
		&ImageScan{},
		&ImageVulnerability{},
		&ImageRegistry{},
		&ScanJob{},
		&KubeScanner{},
		&RemediationPolicy{},
		&RemediationPolicyExecution{},
		&VulnBulletin{},
		&IOCSnapshot{},
		&AgentRule{},
		&SequenceRule{},
		&BehaviorAlert{},
		&HostBaselineState{},
		&Storyline{},
		&StorylineEvent{},
		&MemoryThreat{},
		&HuntQuery{},
		&HostIsolation{},
		&AnomalyAlert{},
		// RBAC: 启动 AutoMigrate 时建 permissions / role_permissions 表
		// 缺这两个 model 导致 /api/v1/rbac/permissions 直接 500（Table doesn't exist）
		&Permission{},
		&RolePermission{},
		&Role{},
		&LoginDevice{},

		// v2.0 多租户: Tenant 必须放在 AllModels 前列实际无序，但
		// 后续 model 加 tenant_id 外键依赖此表存在。
		&Tenant{},
		&TenantConfig{},
	}
)
