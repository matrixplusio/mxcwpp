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
	if p == nil || p.sender == nil {
		return fmt.Errorf("基线下发未接线：CommandSender 为空")
	}

	// PolicyID 不在事件上，经产生该事件的任务反查。
	var task model.FIMTask
	if err := p.db.Where("task_id = ?", ev.TaskID).First(&task).Error; err != nil {
		return fmt.Errorf("查询事件所属任务失败: %w", err)
	}

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

	// 用事件里的新值覆盖该路径。删除类事件则从基线移除，
	// 否则文件已经不在了，基线还留着条目，下一轮又报一次 removed。
	switch ev.ChangeType {
	case "removed", "deleted":
		delete(out.Entries, ev.FilePath)
	default:
		cur := out.Entries[ev.FilePath] // 基线里没有则为零值，added 事件即走此路径
		applyChange(&cur, ev.ChangeDetail)
		out.Entries[ev.FilePath] = cur
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
	if err := p.sender.SendCommand(ev.HostID, cmd); err != nil {
		return fmt.Errorf("下发基线失败: %w", err)
	}

	// 服务端侧同步落库，让两边版本号一致；下发成功才写，避免服务端version
	// 领先于 Agent 实际持有的基线。
	if err := p.persist(&bl, out, ev); err != nil {
		p.logger.Warn("基线已下发但服务端落库失败，版本号将落后于 Agent",
			zap.String("host_id", ev.HostID),
			zap.String("policy_id", bl.PolicyID),
			zap.Error(err))
	}

	p.logger.Info("已确认变更并回写 FIM 基线",
		zap.String("host_id", ev.HostID),
		zap.String("policy_id", task.PolicyID),
		zap.String("file_path", ev.FilePath),
		zap.String("change_type", ev.ChangeType),
		zap.Int("version", out.Version),
		zap.Int("entries", len(out.Entries)))
	return nil
}

// persist 把新版本写回服务端基线表。
func (p *FIMBaselinePusher) persist(bl *model.FIMBaseline, out agentBaseline, ev *model.FIMEvent) error {
	return p.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(bl).Updates(map[string]any{
			"version":     out.Version,
			"entry_count": len(out.Entries),
			"status":      "approved",
		}).Error; err != nil {
			return err
		}
		if ev.ChangeType == "removed" || ev.ChangeType == "deleted" {
			return tx.Where("baseline_id = ? AND file_path = ?", bl.ID, ev.FilePath).
				Delete(&model.FIMBaselineEntry{}).Error
		}
		e := out.Entries[ev.FilePath]
		return tx.Where("baseline_id = ? AND file_path = ?", bl.ID, ev.FilePath).
			Assign(model.FIMBaselineEntry{
				SHA256: e.SHA256, FileSize: e.Size, FileMode: e.Mode,
				UID: e.UID, GID: e.GID, MTime: e.MTime,
			}).
			FirstOrCreate(&model.FIMBaselineEntry{
				BaselineID: bl.ID, FilePath: ev.FilePath,
			}).Error
	})
}

// applyChange 把事件里的变更后状态并入基线条目。
//
// 事件只携带 hash / size / mode 的变更后值（model.ChangeDetail），uid 与 gid 只有
// 一个 OwnerChanged 布尔，没有新值。所以纯属主变更确认后仍会在下一轮复报——
// 要根治得让 Agent 在事件里带上完整的当前条目。这里保留基线中的旧 uid/gid 而不是
// 清零：清零会让 compareEntries 把属主判成从 0 变成真实值，反而每轮都报。
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
}
