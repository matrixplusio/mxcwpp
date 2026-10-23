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

// EngineOutcome 说明某个扫描引擎这次到底做了什么。
//
// 此前引擎不可用或内存不足时返回 (nil, nil)——调用方读到"零威胁、无错误"，
// 于是任务标记 completed、threat_count=0。一台根本没装 ClamAV 的主机，
// 平台报告它没有恶意文件。"没扫"和"扫了没发现"在安全产品里必须能区分：
// 前者是覆盖缺口，后者才是结论。
type EngineOutcome string

const (
	// OutcomeScanned 引擎确实执行了扫描，结果可信。
	OutcomeScanned EngineOutcome = "scanned"
	// OutcomeUnavailable 引擎不存在或前置条件不满足（未安装、内存不足），未执行扫描。
	OutcomeUnavailable EngineOutcome = "unavailable"
	// OutcomeFailed 引擎存在但执行出错，结果不完整。
	OutcomeFailed EngineOutcome = "failed"
)

// EngineReport 是单个引擎的执行回执。
type EngineReport struct {
	Engine  string        `json:"engine"`
	Outcome EngineOutcome `json:"outcome"`
	Reason  string        `json:"reason,omitempty"`
	Threats int           `json:"threats"`
}

// ScanOutcome 是一次扫描任务的整体结论。
type ScanOutcome struct {
	// Status 取值 clean / infected / partial / unavailable。
	//
	//   clean       —— 所有引擎都跑了，没发现威胁
	//   infected    —— 发现威胁
	//   partial     —— 部分引擎未跑或出错，结论不完整
	//   unavailable —— 没有任何引擎可用，本次根本没有扫描发生
	Status  string         `json:"status"`
	Reports []EngineReport `json:"engine_reports"`
	Threats []ScanResult   `json:"threats"`
}

// Summarize 由各引擎回执推导整体结论。
func Summarize(reports []EngineReport, threats []ScanResult) ScanOutcome {
	out := ScanOutcome{Reports: reports, Threats: threats}
	scanned, degraded := 0, 0
	for _, r := range reports {
		switch r.Outcome {
		case OutcomeScanned:
			scanned++
		default:
			degraded++
		}
	}
	switch {
	case scanned == 0:
		// 一个引擎都没跑成：绝不能报 clean。
		out.Status = "unavailable"
	case len(threats) > 0:
		out.Status = "infected"
	case degraded > 0:
		// 跑了一部分且没发现威胁——但覆盖不全，不足以下"干净"的结论。
		out.Status = "partial"
	default:
		out.Status = "clean"
	}
	return out
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
	"/var/mxcwpp/quarantine",
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
