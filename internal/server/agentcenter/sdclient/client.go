// Package sdclient 实现 AgentCenter 向 Manager SD 模块注册/心跳/注销的客户端
package sdclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

const (
	heartbeatInterval = 15 * time.Second
	requestTimeout    = 5 * time.Second
)

// Client 负责 AC 实例向 Manager SD 的生命周期上报
type Client struct {
	managerAddr    string
	instanceID     string
	grpcAddr       string
	httpAddr       string
	internalSecret string     // Manager 内部通信共享密钥
	connCount      func() int // 获取当前在线 Agent 数的回调
	httpClient     *http.Client
	logger         *zap.Logger
}

// NewClient 创建 SD Client (v1 兼容,HTTP + X-Internal-Secret)。
//
// 旧调用方继续使用此构造函数。新代码建议使用 NewClientWithTLS。
//
// managerAddr:    Manager HTTP 地址,如 http://manager:8080
// instanceID:     AC 实例唯一 ID,留空则用 hostname
// grpcAddr:       AC gRPC 地址(Agent 连接用)
// httpAddr:       AC HTTP 管理地址(Manager 探测用)
// internalSecret: 内部通信共享密钥(与 Manager 端 internal_secret 一致)
// connCount:      返回当前在线连接数的回调
func NewClient(managerAddr, instanceID, grpcAddr, httpAddr, internalSecret string, connCount func() int, logger *zap.Logger) *Client {
	c, _ := NewClientWithTLS(managerAddr, instanceID, grpcAddr, httpAddr, internalSecret, MTLSConfig{}, connCount, logger)
	return c
}

// NewClientWithTLS 创建支持 mTLS 的 SD Client (v2.0 新)。
//
// 当 mtls.Enabled = true 时, manager_addr 必须为 https:// 前缀,
// 客户端证书 / 私钥 / CA 证书必须可读。
// 当 mtls.Enabled = false 时, 行为与 NewClient 相同(向后兼容)。
//
// 详见 docs/architecture.md §7 + docs/configuration.md mtls 配置示例.
func NewClientWithTLS(managerAddr, instanceID, grpcAddr, httpAddr, internalSecret string, mtls MTLSConfig, connCount func() int, logger *zap.Logger) (*Client, error) {
	if instanceID == "" {
		if h, err := os.Hostname(); err == nil {
			instanceID = h
		} else {
			instanceID = "unknown-ac"
		}
	}
	httpClient, err := buildHTTPClient(mtls, requestTimeout)
	if err != nil {
		return nil, err
	}
	if logger != nil {
		logger.Info("AC SD client initialized",
			zap.String("instance_id", instanceID),
			zap.String("manager_addr", managerAddr),
			zap.Bool("mtls_enabled", mtls.Enabled),
		)
	}
	return &Client{
		managerAddr:    managerAddr,
		instanceID:     instanceID,
		grpcAddr:       grpcAddr,
		httpAddr:       httpAddr,
		internalSecret: internalSecret,
		connCount:      connCount,
		httpClient:     httpClient,
		logger:         logger,
	}, nil
}

// Start 注册并启动心跳循环，直到 ctx 取消后自动注销
func (c *Client) Start(ctx context.Context) {
	if c.managerAddr == "" {
		c.logger.Warn("AC SD 客户端未配置 manager_addr，跳过服务注册")
		return
	}

	// 初次注册（失败重试，最多 3 次）
	for i := 0; i < 3; i++ {
		if err := c.register(); err != nil {
			c.logger.Warn("AC 注册到 Manager SD 失败，稍后重试",
				zap.Int("attempt", i+1),
				zap.Error(err),
			)
			time.Sleep(3 * time.Second)
			continue
		}
		c.logger.Info("AC 已注册到 Manager SD",
			zap.String("instance_id", c.instanceID),
			zap.String("manager_addr", c.managerAddr),
		)
		break
	}

	// 心跳循环
	go c.heartbeatLoop(ctx)
}

// heartbeatLoop 定期上报心跳，ctx 取消时注销
func (c *Client) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := c.deregister(); err != nil {
				c.logger.Warn("AC 注销失败", zap.Error(err))
			} else {
				c.logger.Info("AC 已从 Manager SD 注销", zap.String("instance_id", c.instanceID))
			}
			return
		case <-ticker.C:
			connCount := 0
			if c.connCount != nil {
				connCount = c.connCount()
			}
			if err := c.heartbeat(int64(connCount)); err != nil {
				c.logger.Warn("AC 心跳上报失败", zap.Error(err))
				// 心跳失败可能是 Manager 重启后丢失注册，尝试重新注册
				_ = c.register()
			}
		}
	}
}

// register 向 Manager 注册 AC 实例
func (c *Client) register() error {
	body, _ := json.Marshal(map[string]string{
		"id":        c.instanceID,
		"grpc_addr": c.grpcAddr,
		"http_addr": c.httpAddr,
	})
	return c.post("/api/v1/internal/ac/register", body)
}

// heartbeat 上报心跳和连接数
func (c *Client) heartbeat(connCount int64) error {
	body, _ := json.Marshal(map[string]any{
		"id":         c.instanceID,
		"conn_count": connCount,
	})
	return c.post("/api/v1/internal/ac/heartbeat", body)
}

// deregister 注销 AC 实例
func (c *Client) deregister() error {
	body, _ := json.Marshal(map[string]string{
		"id": c.instanceID,
	})
	req, err := http.NewRequest(http.MethodDelete, c.managerAddr+"/api/v1/internal/ac/deregister", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.internalSecret != "" {
		req.Header.Set("X-Internal-Secret", c.internalSecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("注销响应异常: %d", resp.StatusCode)
	}
	return nil
}

// post 发送 JSON POST 请求到 Manager
func (c *Client) post(path string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, c.managerAddr+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.internalSecret != "" {
		req.Header.Set("X-Internal-Secret", c.internalSecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Manager 要求重新注册
		return fmt.Errorf("实例未注册，需重新注册")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("响应异常: %d", resp.StatusCode)
	}
	return nil
}
