package biz

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// fimBaselineDataType 是基线下发的 DataType，见 docs/datatype-allocation.md。
//
// Agent 侧接收方（plugins/fim/main.go）自始就存在，发送方一直没有写。后果是
// FIM 基线只在首扫落地一次，此后每轮扫描都拿首扫快照作比对基准：凡相对首扫
// 变化过一次的文件，此后永远判 changed。一次系统包升级因此产出
// 22,588 条永不收敛的告警，而控制台的「确认变更」点了不报错、基线也不动。
const fimBaselineDataType = 6003

// CommandSender 是 Manager 向指定 Agent 下发命令的能力。
// 由 sd.ACDispatcher 实现，此处取接口以便测试替身。
type CommandSender interface {
	SendCommand(agentID string, cmd *grpcProto.Command) error
}

// FIMBaselinePusher 把服务端保存的基线推回 Agent。
type FIMBaselinePusher struct {
	db     *gorm.DB
	sender CommandSender
	logger *zap.Logger
}

func NewFIMBaselinePusher(db *gorm.DB, sender CommandSender, logger *zap.Logger) *FIMBaselinePusher {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &FIMBaselinePusher{db: db, sender: sender, logger: logger}
}

// agentFileEntry 是 Agent 本地基线里的单条记录。
// 字段名必须与 plugins/fim/engine.FileEntry 的 json tag 一致，否则 Agent 解出空值，
// 而空基线条目会让比对逻辑把任何非空文件都判成变更——比不下发更糟。
type agentFileEntry struct {
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode,omitempty"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	MTime  int64  `json:"mtime"`
}

// agentBaseline 对应 plugins/fim/engine.Baseline。
type agentBaseline struct {
	PolicyID  string                    `json:"policy_id"`
	Version   int                       `json:"version"`
	CreatedAt string                    `json:"created_at"`
	Entries   map[string]agentFileEntry `json:"entries"`
}

// PushForConfirmedEvent 在一条 FIM 事件被确认为合法变更后，把该文件的新状态
// 并入基线并下发给该主机。
//
// 只更新被确认的那一个路径，不整体重建：未经确认的其它变更必须继续告警，
// 否则一次确认就等于批准了这台机器上所有待确认的变更。
func (p *FIMBaselinePusher) PushForConfirmedEvent(ev *model.FIMEvent) error {
	return p.AdoptDecided([]*model.FIMEvent{ev})
}

// AdoptDecided 把一批已有定论的事件并入各自主机的基线并下发。
//
// 「有定论」指这条变更已经走完处理流程——被确认为合法、升级成了告警、或判定
// 无需告警。三种情形的共同点是系统对它已经表过态，再逐轮重复报告同一件事
// 不增加任何信息。不并入基线的后果是它每轮扫描复报一次，形成每天数量几乎
// 不变的稳定复读，而这些文件的内容早已不再变化。
//
// 必须按主机批量处理：下发的是整份基线而非增量，逐事件调用会把同一份基线
// 重复下发几十上百次，还会让版本号连跳。
func (p *FIMBaselinePusher) AdoptDecided(events []*model.FIMEvent) error {
	if p == nil || p.sender == nil {
		return fmt.Errorf("基线下发未接线：CommandSender 为空")
	}
	if len(events) == 0 {
		return nil
	}

	// 同一主机同一策略的事件合成一次下发。
	type groupKey struct{ hostID, taskID string }
	groups := make(map[groupKey][]*model.FIMEvent)
	order := make([]groupKey, 0, len(events))
	for _, ev := range events {
		if ev == nil {
			continue
		}
		k := groupKey{hostID: ev.HostID, taskID: ev.TaskID}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], ev)
	}

	var firstErr error
	for _, k := range order {
		if err := p.adoptOneHost(k.hostID, k.taskID, groups[k]); err != nil {
			p.logger.Warn("并入 FIM 基线失败，这些路径下一轮会复报",
				zap.String("host_id", k.hostID),
				zap.Int("events", len(groups[k])),
				zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// adoptOneHost 处理单台主机上的一批事件：读一次基线、合并全部变更、下发一次。
func (p *FIMBaselinePusher) adoptOneHost(hostID, taskID string, events []*model.FIMEvent) error {
	// PolicyID 不在事件上，经产生该事件的任务反查。
	var task model.FIMTask
	if err := p.db.Where("task_id = ?", taskID).First(&task).Error; err != nil {
		return fmt.Errorf("查询事件所属任务失败: %w", err)
	}
	ev := events[0]

	var bl model.FIMBaseline
	if err := p.db.Where("policy_id = ? AND host_id = ?", task.PolicyID, ev.HostID).
		First(&bl).Error; err != nil {
		return fmt.Errorf("查询主机基线失败: %w", err)
	}

	var entries []model.FIMBaselineEntry
	if err := p.db.Where("baseline_id = ?", bl.ID).Find(&entries).Error; err != nil {
		return fmt.Errorf("查询基线条目失败: %w", err)
	}

	out := agentBaseline{
		PolicyID:  bl.PolicyID,
		Version:   bl.Version + 1,
		CreatedAt: time.Now().Format(time.RFC3339),
		Entries:   make(map[string]agentFileEntry, len(entries)+1),
	}
	for _, e := range entries {
		out.Entries[e.FilePath] = agentFileEntry{
			SHA256: e.SHA256, Size: e.FileSize, Mode: e.FileMode,
			UID: e.UID, GID: e.GID, MTime: e.MTime,
		}
	}

	// 用事件里的新值覆盖对应路径。删除类事件则从基线移除，
	// 否则文件已经不在了，基线还留着条目，下一轮又报一次 removed。
	for _, e := range events {
		switch e.ChangeType {
		case "removed", "deleted":
			delete(out.Entries, e.FilePath)
		default:
			cur := out.Entries[e.FilePath] // 基线里没有则为零值，added 事件即走此路径
			applyChange(&cur, e.ChangeDetail)
			out.Entries[e.FilePath] = cur
		}
	}

	payload, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("序列化基线失败: %w", err)
	}

	cmd := &grpcProto.Command{Tasks: []*grpcProto.Task{{
		DataType:   fimBaselineDataType,
		ObjectName: "fim",
		Data:       string(payload),
		Token:      bl.TaskID,
	}}}
	if err := p.sender.SendCommand(hostID, cmd); err != nil {
		return fmt.Errorf("下发基线失败: %w", err)
	}

	// 服务端侧同步落库，让两边版本号一致；下发成功才写，避免服务端version
	// 领先于 Agent 实际持有的基线。
	if err := p.persist(&bl, out, events); err != nil {
		p.logger.Warn("基线已下发但服务端落库失败，版本号将落后于 Agent",
			zap.String("host_id", hostID),
			zap.String("policy_id", bl.PolicyID),
			zap.Error(err))
	}

	p.logger.Info("已并入 FIM 基线",
		zap.String("host_id", hostID),
		zap.String("policy_id", task.PolicyID),
		zap.Int("paths", len(events)),
		zap.Int("version", out.Version),
		zap.Int("entries", len(out.Entries)))
	return nil
}

// persist 把新版本写回服务端基线表。
func (p *FIMBaselinePusher) persist(bl *model.FIMBaseline, out agentBaseline, events []*model.FIMEvent) error {
	return p.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(bl).Updates(map[string]any{
			"version":     out.Version,
			"entry_count": len(out.Entries),
			"status":      "approved",
		}).Error; err != nil {
			return err
		}
		for _, ev := range events {
			if ev.ChangeType == "removed" || ev.ChangeType == "deleted" {
				if err := tx.Where("baseline_id = ? AND file_path = ?", bl.ID, ev.FilePath).
					Delete(&model.FIMBaselineEntry{}).Error; err != nil {
					return err
				}
				continue
			}
			e := out.Entries[ev.FilePath]
			if err := tx.Where("baseline_id = ? AND file_path = ?", bl.ID, ev.FilePath).
				Assign(model.FIMBaselineEntry{
					SHA256: e.SHA256, FileSize: e.Size, FileMode: e.Mode,
					UID: e.UID, GID: e.GID, MTime: e.MTime,
				}).
				FirstOrCreate(&model.FIMBaselineEntry{
					BaselineID: bl.ID, FilePath: ev.FilePath,
				}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// applyChange 把事件里的变更后状态并入基线条目。
//
// uid / gid / mtime 用指针接收：老版本 Agent 不送这三个字段，此时保留基线中的旧值，
// 不能清零——uid 0 是 root，清零会让 compareEntries 把属主判成从 0 变成真实值，
// 于是每轮都报。新版本 Agent 送来当前值，属主变更才能真正收敛。
func applyChange(e *agentFileEntry, d model.ChangeDetail) {
	if d.HashAfter != "" {
		e.SHA256 = d.HashAfter
	}
	if d.ModeAfter != "" {
		e.Mode = d.ModeAfter
	}
	if d.SizeAfter != "" {
		if n, err := strconv.ParseInt(d.SizeAfter, 10, 64); err == nil {
			e.Size = n
		}
	}
	if d.UIDAfter != nil {
		e.UID = *d.UIDAfter
	}
	if d.GIDAfter != nil {
		e.GID = *d.GIDAfter
	}
	if d.MTimeAfter != nil {
		e.MTime = *d.MTimeAfter
	}
}
