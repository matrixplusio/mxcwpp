// Package honeypot 实现反勒索 honeypot 服务端检测逻辑。
//
// 设计文档: ref/07-病毒.md §5
//
// 客户端模式 (Agent 端 av-scanner 插件, Sprint 4 实现):
//   - 在 /root/ /home/*/ 等关键目录投放 6 类诱饵文件:
//   - decoy.docx / decoy.xlsx / decoy.png / decoy.csv / decoy.pdf / .important.txt
//   - 用 fanotify FAN_MODIFY | FAN_CLOSE_WRITE 监控
//   - 命中即上报 + 立即 SIGKILL 触发进程
//
// 服务端 (本 PR):
//   - 接收 Agent 上报的 honeypot 触发事件 (DataType 7020-7029 预留)
//   - 关联进程 + 用户 + 时间窗内的其他可疑事件
//   - 产 Alert + 推荐隔离主机 + 触发 av-scanner 全盘扫
package honeypot

import (
	"context"
	"encoding/json"
	"time"
)

// HoneypotTrigger 是单次 honeypot 命中事件。
type HoneypotTrigger struct {
	HostID        string
	DecoyPath     string // 诱饵文件路径
	DecoyType     string // docx / xlsx / png / csv / pdf / txt
	TriggeringPID int32
	TriggeringExe string
	TriggeringUID int32
	Operation     string // open / write / rename / delete
	Timestamp     time.Time
}

// Detector 服务端反勒索 honeypot 决策器。
type Detector struct {
	// 后续可加配置 (白名单进程 / 合法运维操作放行等)
}

// NewDetector 构造。
func NewDetector() *Detector { return &Detector{} }

// Evaluate 处理一次 honeypot 触发,返回 Alert payload。
//
// 当前简化策略: 任何 honeypot 命中都立即产 critical Alert
// (诱饵文件设计上不应被合法访问)。
func (d *Detector) Evaluate(_ context.Context, t HoneypotTrigger) []byte {
	ts := t.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	payload, _ := json.Marshal(map[string]any{
		"host_id":        t.HostID,
		"decoy_path":     t.DecoyPath,
		"decoy_type":     t.DecoyType,
		"triggering_pid": t.TriggeringPID,
		"triggering_exe": t.TriggeringExe,
		"triggering_uid": t.TriggeringUID,
		"operation":      t.Operation,
		"timestamp":      ts,
		"ransomware_indicators": []string{
			"honeypot_decoy_modified",
			"decoy_type:" + t.DecoyType,
		},
		"would_action": map[string]any{
			"type":   "kill_pid_and_isolate",
			"target": t.TriggeringPID,
			"reason": "反勒索 honeypot 命中: " + t.DecoyPath + " 被进程 " + t.TriggeringExe + " 修改",
			"escalate": map[string]any{
				"isolate_host":       true,
				"trigger_av_full":    true,
				"notify_severity":    "critical",
				"forensics_snapshot": true,
			},
		},
	})
	return payload
}
