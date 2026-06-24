package sd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const dispatchTimeout = 5 * time.Second

// ACDispatcher 实现 SendCommand 接口，优先精准路由到目标 AC，失败时退化为广播
type ACDispatcher struct {
	registry    *Registry
	redisClient *redis.Client
	httpClient  *http.Client
	logger      *zap.Logger
}

// NewACDispatcher 创建 ACDispatcher
func NewACDispatcher(registry *Registry, redisClient *redis.Client, logger *zap.Logger) *ACDispatcher {
	return &ACDispatcher{
		registry:    registry,
		redisClient: redisClient,
		httpClient:  &http.Client{Timeout: dispatchTimeout},
		logger:      logger,
	}
}

// commandReq 对应 httptrans/handler.go 的 sendCommandReq
type commandReq struct {
	AgentID string    `json:"agent_id"`
	Tasks   []taskDTO `json:"tasks"`
}

// taskDTO 对应 httptrans/handler.go 的 taskReq（字段与 grpcProto.Task 一一对应）
type taskDTO struct {
	DataType   int32  `json:"data_type"`
	ObjectName string `json:"object_name"`
	Data       string `json:"data"`
	Token      string `json:"token"`
}

// SendCommand 优先按 agent:ac:{agentID} 精准路由，失败时退化为广播
// 实现了 agentcenter/service.TaskService 所需的 SendCommand 接口
func (d *ACDispatcher) SendCommand(agentID string, cmd *grpcProto.Command) error {
	req := commandReq{
		AgentID: agentID,
		Tasks:   make([]taskDTO, 0, len(cmd.Tasks)),
	}
	for _, t := range cmd.Tasks {
		req.Tasks = append(req.Tasks, taskDTO{
			DataType:   t.DataType,
			ObjectName: t.ObjectName,
			Data:       t.Data,
			Token:      t.Token,
		})
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化命令失败: %w", err)
	}

	if d.redisClient != nil {
		if acID, err := d.redisClient.Get(context.Background(), "agent:ac:"+agentID).Result(); err == nil && acID != "" {
			if inst := d.registry.GetByID(acID); inst != nil {
				if err := d.sendToInstance(inst, agentID, body); err == nil {
					d.logger.Info("精准路由成功",
						zap.String("agent_id", agentID),
						zap.String("ac_id", inst.ID),
					)
					return nil
				} else {
					d.logger.Warn("精准路由失败，降级广播",
						zap.String("agent_id", agentID),
						zap.String("ac_id", acID),
						zap.Error(err),
					)
				}
			} else {
				d.logger.Debug("精准路由命中失效映射，降级广播",
					zap.String("agent_id", agentID),
					zap.String("ac_id", acID),
				)
			}
		} else if err != nil && err != redis.Nil {
			d.logger.Warn("读取 agent:ac: Redis 映射失败，降级广播",
				zap.String("agent_id", agentID),
				zap.Error(err),
			)
		}
	}

	instances := d.registry.ListHealthy()
	if len(instances) == 0 {
		return fmt.Errorf("没有可用的 AgentCenter 实例")
	}

	// 广播给所有健康 AC，至少一个成功即可
	var lastErr error
	successCount := 0
	for _, inst := range instances {
		if err := d.sendToInstance(inst, agentID, body); err == nil {
			successCount++
		} else {
			lastErr = err
		}
	}

	if successCount > 0 {
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("所有 AC 均无法送达 agent %s", agentID)
}

func (d *ACDispatcher) sendToInstance(inst *ACInstance, agentID string, body []byte) error {
	url := fmt.Sprintf("http://%s/command", inst.HTTPAddr)
	resp, err := d.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		d.logger.Debug("AC 命令转发失败",
			zap.String("ac_id", inst.ID),
			zap.String("agent_id", agentID),
			zap.Error(err),
		)
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusServiceUnavailable:
		return fmt.Errorf("AC %s: agent not connected", inst.ID)
	default:
		return fmt.Errorf("AC %s 返回 %d", inst.ID, resp.StatusCode)
	}
}

// depInstallReq 是发送给 AC /dependency/install 的请求体
type depInstallReq struct {
	AgentID     string `json:"agent_id"`
	Name        string `json:"name"`
	Action      string `json:"action"`
	Version     string `json:"version"`
	RequestID   string `json:"request_id"`
	DownloadURL string `json:"download_url"`
}

// SendDependencyInstall 向指定 Agent 发送依赖安装命令（通过 AC HTTP 转发）
func (d *ACDispatcher) SendDependencyInstall(agentID, name, action, version, requestID, downloadURL string) error {
	req := depInstallReq{
		AgentID:     agentID,
		Name:        name,
		Action:      action,
		Version:     version,
		RequestID:   requestID,
		DownloadURL: downloadURL,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化依赖安装命令失败: %w", err)
	}

	// 精准路由
	if d.redisClient != nil {
		if acID, err := d.redisClient.Get(context.Background(), "agent:ac:"+agentID).Result(); err == nil && acID != "" {
			if inst := d.registry.GetByID(acID); inst != nil {
				if err := d.sendDepInstallToInstance(inst, body); err == nil {
					return nil
				}
			}
		}
	}

	// 广播
	instances := d.registry.ListHealthy()
	if len(instances) == 0 {
		return fmt.Errorf("没有可用的 AgentCenter 实例")
	}

	var lastErr error
	for _, inst := range instances {
		if err := d.sendDepInstallToInstance(inst, body); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("所有 AC 均无法送达 agent %s", agentID)
}

func (d *ACDispatcher) sendDepInstallToInstance(inst *ACInstance, body []byte) error {
	url := fmt.Sprintf("http://%s/dependency/install", inst.HTTPAddr)
	resp, err := d.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("AC %s 返回 %d", inst.ID, resp.StatusCode)
}
