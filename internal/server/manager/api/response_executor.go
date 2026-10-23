package api

import (
	"encoding/json"
	"errors"
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// hostResponseExecutor 执行主机类处置动作。
//
// 这是处置的唯一执行出口：命令下发从各 handler 收拢到这里，
// 使"未审批不得执行"成为结构上的保证，而不是每个 handler 各自记得去检查。
type hostResponseExecutor struct {
	db           *gorm.DB
	logger       *zap.Logger
	acDispatcher *sd.ACDispatcher
}

func newHostResponseExecutor(db *gorm.DB, logger *zap.Logger, d *sd.ACDispatcher) *hostResponseExecutor {
	return &hostResponseExecutor{db: db, logger: logger, acDispatcher: d}
}

// isolationParams 是隔离动作的参数，随申请一起存下以便执行与回滚时复用。
type isolationParams struct {
	Level   string `json:"level"`
	Timeout int    `json:"timeout"`
	Reason  string `json:"reason"`
}

// Execute 执行处置动作。
func (e *hostResponseExecutor) Execute(act *model.ResponseAction) (string, error) {
	switch act.Action {
	case model.ResponseActionIsolateHost:
		return e.isolate(act)
	case model.ResponseActionReleaseHost:
		return e.release(act)
	default:
		return "", fmt.Errorf("未知处置动作: %s", act.Action)
	}
}

// Rollback 回滚处置：隔离的反向操作是解除隔离，反之亦然。
func (e *hostResponseExecutor) Rollback(act *model.ResponseAction) error {
	switch act.Action {
	case model.ResponseActionIsolateHost:
		_, err := e.release(act)
		return err
	case model.ResponseActionReleaseHost:
		_, err := e.isolate(act)
		return err
	default:
		return fmt.Errorf("动作 %s 不支持回滚", act.Action)
	}
}

func (e *hostResponseExecutor) isolate(act *model.ResponseAction) (string, error) {
	p := e.params(act)
	if err := e.dispatch(act.Target, map[string]any{
		"action":  "isolate",
		"level":   p.Level,
		"reason":  p.Reason,
		"timeout": p.Timeout,
	}); err != nil {
		return "", err
	}
	now := model.Now()
	record := model.HostIsolation{
		HostID:     act.Target,
		Level:      p.Level,
		Reason:     p.Reason,
		Timeout:    p.Timeout,
		Status:     "active",
		Source:     "manual",
		CreatedBy:  act.ApprovedBy,
		IsolatedAt: &now,
	}
	if err := e.db.Create(&record).Error; err != nil {
		// 命令已下发但记录没落库：状态会与实际不符，必须报错而不是当作成功。
		return "", fmt.Errorf("隔离命令已下发但记录写入失败: %w", err)
	}
	return fmt.Sprintf("已隔离 %s（级别 %s）", act.Target, p.Level), nil
}

func (e *hostResponseExecutor) release(act *model.ResponseAction) (string, error) {
	p := e.params(act)
	if err := e.dispatch(act.Target, map[string]any{
		"action": "release",
		"reason": p.Reason,
	}); err != nil {
		return "", err
	}
	now := model.Now()
	e.db.Model(&model.HostIsolation{}).
		Where("host_id = ? AND status = ?", act.Target, "active").
		Updates(map[string]any{
			"status":      "released",
			"released_at": &now,
			"released_by": act.ApprovedBy,
		})
	return fmt.Sprintf("已解除隔离 %s", act.Target), nil
}

// params 解析申请里保存的参数，缺省时给出安全默认值。
func (e *hostResponseExecutor) params(act *model.ResponseAction) isolationParams {
	p := isolationParams{Level: "standard", Timeout: 14400, Reason: act.Reason}
	if act.Result != "" {
		_ = json.Unmarshal([]byte(act.Result), &p)
	}
	if p.Level == "" {
		p.Level = "standard"
	}
	if p.Timeout <= 0 {
		p.Timeout = 14400
	}
	if p.Reason == "" {
		p.Reason = act.Reason
	}
	return p
}

// dispatch 下发命令到 Agent。
//
// dispatcher 缺失必须报错：原实现打一条 warn 后 return nil，
// 于是"隔离命令未下发"被当作隔离成功——界面显示主机已隔离，实际流量照通。
func (e *hostResponseExecutor) dispatch(hostID string, task map[string]any) error {
	if e.acDispatcher == nil {
		return errors.New("AC dispatcher 未初始化，处置命令无法下发")
	}
	payload, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("序列化处置命令失败: %w", err)
	}
	cmd := &grpcProto.Command{
		Tasks: []*grpcProto.Task{{
			DataType:   9997,
			ObjectName: "edr",
			Data:       string(payload),
		}},
	}
	if err := e.acDispatcher.SendCommand(hostID, cmd); err != nil {
		return fmt.Errorf("下发处置命令失败: %w", err)
	}
	return nil
}
