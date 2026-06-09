package transfer

import (
	"encoding/json"
	"fmt"
	"strings"

	grpcProto "github.com/imkerbos/mxsec-platform/api/proto/grpc"
)

// PushToAgent 实现 commandsub.AgentPusher interface。
//
// 把 commandsub 收到的 Engine 命令转成 grpcProto.Command 后通过 SendCommand 推送。
// 返回 (true, nil) Agent 在线已入队;(false, nil) Agent 离线;(false, err) 其他错误。
func (s *Service) PushToAgent(agentID string, command []byte) (bool, error) {
	cmd, err := decodeEngineCommand(command)
	if err != nil {
		return false, fmt.Errorf("decode engine command: %w", err)
	}
	if err := s.SendCommand(agentID, cmd); err != nil {
		// Agent 未连接视为离线 (false, nil),不算错误
		if strings.HasPrefix(err.Error(), "agent 未连接") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// PushToAgents 批量推送。
func (s *Service) PushToAgents(agentIDs []string, command []byte) (succeeded, failed int, err error) {
	cmd, err := decodeEngineCommand(command)
	if err != nil {
		return 0, len(agentIDs), fmt.Errorf("decode engine command: %w", err)
	}
	for _, id := range agentIDs {
		if e := s.SendCommand(id, cmd); e != nil {
			failed++
			continue
		}
		succeeded++
	}
	return succeeded, failed, nil
}

// decodeEngineCommand 把 commandsub 的命令 JSON 转 grpcProto.Command。
//
// 命令格式 (engine 端):
//
//	{
//	  "type": "agent_config" | "agent_restart",
//	  "payload": { ... 各 type 独立 schema ... }
//	}
//
// PR36 仅支持 agent_config + agent_restart 两种 (Engine→AC→Agent 通用通道),
// 其他类型 (Task/AgentUpdate/DependencyInstall) 由后续 PR 扩展。
func decodeEngineCommand(raw []byte) (*grpcProto.Command, error) {
	var envelope struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		// 兼容: 不是 envelope 格式时, 整个 raw 作为 AgentConfig.Extra["payload"]
		return &grpcProto.Command{
			AgentConfig: &grpcProto.AgentConfig{
				Extra: map[string]string{"payload": string(raw)},
			},
		}, nil
	}

	cmd := &grpcProto.Command{}
	switch envelope.Type {
	case "agent_config", "":
		cmd.AgentConfig = &grpcProto.AgentConfig{
			Extra: map[string]string{"payload": string(envelope.Payload)},
		}
	case "agent_restart":
		cmd.AgentRestart = true
	default:
		cmd.AgentConfig = &grpcProto.AgentConfig{
			Extra: map[string]string{
				"payload": string(raw),
				"type":    envelope.Type,
			},
		}
	}
	return cmd, nil
}
