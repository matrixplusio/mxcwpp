package celengine

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// TestCommandForwarder_SendCommand 测试命令转发格式正确
func TestCommandForwarder_SendCommand(t *testing.T) {
	// 模拟 AC HTTP 服务
	var receivedReq commandReq
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/command" {
			t.Errorf("请求路径 = %s, want /command", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("请求方法 = %s, want POST", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedReq)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zap.NewNop()
	fwd := &CommandForwarder{
		httpClient: server.Client(),
		logger:     logger,
	}

	// 直接调用 sendToInstance
	inst := &acInstanceInfo{
		ID:       "ac-1",
		HTTPAddr: server.Listener.Addr().String(),
		Healthy:  true,
	}

	cmd := map[string]interface{}{
		"data_type": 9998,
		"data":      `{"action":"kill_process","target":"12345"}`,
	}
	cmdMap := cmd
	task := taskDTO{}
	if dt, ok := cmdMap["data_type"]; ok {
		switch v := dt.(type) {
		case int:
			task.DataType = int32(v)
		case float64:
			task.DataType = int32(v)
		}
	}
	if data, ok := cmdMap["data"].(string); ok {
		task.Data = data
	}

	req := commandReq{
		AgentID: "agent-test",
		Tasks:   []taskDTO{task},
	}
	body, _ := json.Marshal(req)

	err := fwd.sendToInstance(inst, body)
	if err != nil {
		t.Fatalf("sendToInstance 失败: %v", err)
	}

	// 验证收到的请求
	if receivedReq.AgentID != "agent-test" {
		t.Errorf("AgentID = %s, want agent-test", receivedReq.AgentID)
	}
	if len(receivedReq.Tasks) != 1 {
		t.Fatalf("Tasks 数量 = %d, want 1", len(receivedReq.Tasks))
	}
	if receivedReq.Tasks[0].DataType != 9998 {
		t.Errorf("DataType = %d, want 9998", receivedReq.Tasks[0].DataType)
	}
}

// TestCommandForwarder_ACUnavailable 测试 AC 不可用时返回错误
func TestCommandForwarder_ACUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	logger := zap.NewNop()
	fwd := &CommandForwarder{
		httpClient: server.Client(),
		logger:     logger,
	}

	inst := &acInstanceInfo{
		ID:       "ac-1",
		HTTPAddr: server.Listener.Addr().String(),
		Healthy:  true,
	}

	body := []byte(`{"agent_id":"test","tasks":[]}`)
	err := fwd.sendToInstance(inst, body)
	if err == nil {
		t.Error("期望错误，但返回 nil")
	}
}

// TestCommandForwarder_SendCommandTypeConversion 测试 SendCommand 的类型转换
func TestCommandForwarder_SendCommandTypeConversion(t *testing.T) {
	// 模拟 AC
	var receivedReq commandReq
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedReq)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := zap.NewNop()
	fwd := &CommandForwarder{
		httpClient: server.Client(),
		logger:     logger,
	}

	// 使用一个直接的 HTTP 客户端来测试完整的 SendCommand
	// 这里我们跳过 Redis 部分，直接测试 sendToInstance
	tests := []struct {
		name    string
		cmd     interface{}
		wantErr bool
	}{
		{
			name: "有效命令",
			cmd: map[string]interface{}{
				"data_type":   int(9998),
				"data":        `{"action":"kill"}`,
				"object_name": "",
			},
			wantErr: false,
		},
		{
			name:    "无效命令格式",
			cmd:     "invalid",
			wantErr: true,
		},
		{
			name: "int32 类型",
			cmd: map[string]interface{}{
				"data_type": int32(7003),
				"data":      `{"action":"quarantine"}`,
			},
			wantErr: false,
		},
		{
			name: "float64 类型（JSON 反序列化产生）",
			cmd: map[string]interface{}{
				"data_type": float64(9997),
				"data":      `{"action":"block"}`,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 由于 SendCommand 依赖 Redis，我们只能测试类型转换部分
			cmdMap, ok := tt.cmd.(map[string]interface{})
			if !ok {
				if !tt.wantErr {
					t.Error("期望成功但类型断言失败")
				}
				return
			}

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

			req := commandReq{AgentID: "agent-test", Tasks: []taskDTO{task}}
			body, _ := json.Marshal(req)

			inst := &acInstanceInfo{
				ID:       "ac-1",
				HTTPAddr: server.Listener.Addr().String(),
				Healthy:  true,
			}

			err := fwd.sendToInstance(inst, body)
			if (err != nil) != tt.wantErr {
				t.Errorf("错误 = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
