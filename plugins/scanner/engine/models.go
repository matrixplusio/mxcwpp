// Package engine 提供扫描引擎的核心功能
package engine

import "time"

// DataType 常量
const (
	DataTypeScanTask      int32 = 7000 // 扫描任务（下行）
	DataTypeScanResult    int32 = 7001 // 扫描结果（上行）
	DataTypeScanComplete  int32 = 7002 // 扫描任务完成信号
	DataTypeQuarantineCmd int32 = 7003 // 隔离/删除命令（下行）
	DataTypeQuarantineAck int32 = 7004 // 隔离/删除结果（上行）
)

// ScanRequest 扫描请求
type ScanRequest struct {
	TaskID   string   `json:"task_id"`
	ScanType string   `json:"scan_type"` // quick, full, custom
	Paths    []string `json:"paths"`     // 自定义扫描路径
}

// ScanResult 单个扫描结果
type ScanResult struct {
	FilePath   string    `json:"file_path"`
	ThreatName string    `json:"threat_name"`
	ThreatType string    `json:"threat_type"` // virus, trojan, worm, ransomware, rootkit, miner, backdoor, other
	Severity   string    `json:"severity"`    // critical, high, medium, low
	FileHash   string    `json:"file_hash"`
	FileSize   int64     `json:"file_size"`
	Engine     string    `json:"engine"` // clamav, yara
	RuleName   string    `json:"rule_name,omitempty"`
	DetectedAt time.Time `json:"detected_at"`
}

// QuarantineRequest 隔离/删除请求
type QuarantineRequest struct {
	TaskID   string `json:"task_id"`
	FilePath string `json:"file_path"`
	FileHash string `json:"file_hash"`
	Action   string `json:"action"` // quarantine, delete
}

// QuarantineResult 隔离/删除结果
type QuarantineResult struct {
	FilePath       string `json:"file_path"`
	Action         string `json:"action"`
	Status         string `json:"status"` // success, failed
	QuarantinePath string `json:"quarantine_path,omitempty"`
	FilePermission string `json:"file_permission,omitempty"`
	FileOwner      string `json:"file_owner,omitempty"`
	ErrorMsg       string `json:"error_msg,omitempty"`
}

// DefaultQuickPaths 快速扫描的默认路径
var DefaultQuickPaths = []string{
	"/tmp",
	"/var/tmp",
	"/dev/shm",
	"/root",
	"/home",
}

// DefaultFullPaths 全盘扫描的默认路径
var DefaultFullPaths = []string{
	"/",
}

// DefaultExcludePaths 扫描排除路径
var DefaultExcludePaths = []string{
	"/proc",
	"/sys",
	"/dev",
	"/run",
	"/var/lib/clamav",
	"/var/mxsec/quarantine",
}

// ThreatSeverityMap 根据引擎和威胁类型映射严重级别
var ThreatSeverityMap = map[string]string{
	"ransomware": "critical",
	"rootkit":    "critical",
	"backdoor":   "high",
	"trojan":     "high",
	"miner":      "high",
	"virus":      "medium",
	"worm":       "medium",
	"other":      "low",
}
