// Package celengine - 命令转发器
// Consumer 侧通过 Redis 查找 Agent 所在 AC 实例，HTTP 转发命令
package celengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const forwardTimeout = 5 * time.Second

// acInstanceInfo AC 实例信息（与 sd.ACInstance JSON 字段对应）
type acInstanceInfo struct {
	ID       string `json:"id"`
	HTTPAddr string `json:"http_addr"`
	Healthy  bool   `json:"healthy"`
}

// commandReq AC /command 端点的请求体
type commandReq struct {
	AgentID string    `json:"agent_id"`
	Tasks   []taskDTO `json:"tasks"`
}

type taskDTO struct {
	DataType   int32  `json:"data_type"`
	ObjectName string `json:"object_name"`
	Data       string `json:"data"`
}

// CommandForwarder 实现 AutoResponder 的 dispatcher 接口
// 通过 Redis 查找 AC 实例，HTTP 转发命令
type CommandForwarder struct {
	redisClient *redis.Client
	httpClient  *http.Client
	logger      *zap.Logger
}

// NewCommandForwarder 创建命令转发器
func NewCommandForwarder(redisClient *redis.Client, logger *zap.Logger) *CommandForwarder {
	return &CommandForwarder{
		redisClient: redisClient,
		httpClient:  &http.Client{Timeout: forwardTimeout},
		logger:      logger,
	}
}

// SendCommand 实现 dispatcher 接口
// cmd 为 map[string]interface{}，包含 data_type, data, object_name
func (f *CommandForwarder) SendCommand(agentID string, cmd interface{}) error {
	cmdMap, ok := cmd.(map[string]interface{})
	if !ok {
		return fmt.Errorf("无效的命令格式: %T", cmd)
	}

	// 构建 taskDTO
	task := taskDTO{}
	if dt, ok := cmdMap["data_type"]; ok {
		switch v := dt.(type) {
		case int:
			task.DataType = int32(v)
		case int32:
			task.DataType = v
		case float64:
			task.DataType = int32(v)
		}
	}
	if data, ok := cmdMap["data"].(string); ok {
		task.Data = data
	}
	if obj, ok := cmdMap["object_name"].(string); ok {
		task.ObjectName = obj
	}

	req := commandReq{
		AgentID: agentID,
		Tasks:   []taskDTO{task},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化命令失败: %w", err)
	}

	// 优先精准路由
	ctx := context.Background()
	if acID, err := f.redisClient.Get(ctx, "agent:ac:"+agentID).Result(); err == nil && acID != "" {
		inst, err := f.getACInstance(ctx, acID)
		if err == nil && inst != nil && inst.Healthy {
			if err := f.sendToInstance(inst, body); err == nil {
				f.logger.Info("自动响应命令精准路由成功",
					zap.String("agent_id", agentID),
					zap.String("ac_id", inst.ID),
					zap.Int32("data_type", task.DataType),
				)
				return nil
			}
		}
	}

	// 降级广播
	instances, err := f.listHealthyInstances(ctx)
	if err != nil || len(instances) == 0 {
		return fmt.Errorf("没有可用的 AgentCenter 实例")
	}

	var lastErr error
	for _, inst := range instances {
		if err := f.sendToInstance(inst, body); err == nil {
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

// getACInstance 从 Redis hash 获取单个 AC 实例
func (f *CommandForwarder) getACInstance(ctx context.Context, acID string) (*acInstanceInfo, error) {
	data, err := f.redisClient.HGet(ctx, "ac:instances", acID).Result()
	if err != nil {
		return nil, err
	}
	var inst acInstanceInfo
	if err := json.Unmarshal([]byte(data), &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

// listHealthyInstances 列出所有健康的 AC 实例
func (f *CommandForwarder) listHealthyInstances(ctx context.Context) ([]*acInstanceInfo, error) {
	all, err := f.redisClient.HGetAll(ctx, "ac:instances").Result()
	if err != nil {
		return nil, err
	}
	var healthy []*acInstanceInfo
	for _, v := range all {
		var inst acInstanceInfo
		if err := json.Unmarshal([]byte(v), &inst); err != nil {
			continue
		}
		if inst.Healthy && inst.HTTPAddr != "" {
			healthy = append(healthy, &inst)
		}
	}
	return healthy, nil
}

// sendToInstance 向单个 AC 实例发送命令
func (f *CommandForwarder) sendToInstance(inst *acInstanceInfo, body []byte) error {
	url := fmt.Sprintf("http://%s/command", inst.HTTPAddr)
	resp, err := f.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("AC %s 返回 %d", inst.ID, resp.StatusCode)
}
