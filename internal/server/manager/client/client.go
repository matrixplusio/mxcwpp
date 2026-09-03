// Package client — Manager 跨进程调用 Engine/VulnSync/LLMProxy 的抽象接口 (A8 接口骨架).
//
// 当前 Manager 直接 import engine/vulnsync/llmproxy 跨边界, 本包定义 gRPC 化的
// 标准接口. 后续 PR 用 gRPC 实现替换 inproc 实现, Manager 业务代码无需改.
//
// 用法:
//
//	cli := client.New(client.Config{
//	    EngineAddr:   "engine:50051",
//	    VulnsyncAddr: "vulnsync:50052",
//	    LLMProxyAddr: "llmproxy:50053",
//	    UseGRPC:      true, // 生产环境 true, 测试/dev false 回 inproc
//	})
//	defer cli.Close()
//
//	if err := cli.Engine.KubeBaselineCheck(ctx, clusterID); err != nil { ... }
package client

import (
	"context"
	"errors"
	"time"
)

// EngineClient 抽象 Engine 跨进程调用.
type EngineClient interface {
	// KubeBaselineCheck 触发指定集群 CIS 基线扫描, 返回结果摘要.
	KubeBaselineCheck(ctx context.Context, clusterID string) (*KubeBaselineResult, error)
	// QueryAnomaly 查近 window 时间内异常.
	QueryAnomaly(ctx context.Context, hostID string, window time.Duration) ([]Anomaly, error)
}

// VulnSyncClient 抽象 VulnSync.
type VulnSyncClient interface {
	// TriggerSync 触发指定 source (nvd / redhat / cnnvd / exploitdb 等) 同步.
	TriggerSync(ctx context.Context, source string) error
	// LookupAdvisory 查询单 CVE 详情.
	LookupAdvisory(ctx context.Context, cve string) (*Advisory, error)
}

// LLMProxyClient 抽象 LLMProxy.
type LLMProxyClient interface {
	Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
	SummarizeIncident(ctx context.Context, incidentID string) (string, error)
}

// Config 客户端聚合配置.
type Config struct {
	EngineAddr   string
	VulnsyncAddr string
	LLMProxyAddr string
	UseGRPC      bool          // true=gRPC 跨进程, false=inproc (dev/test 可用)
	DialTimeout  time.Duration // gRPC dial timeout (默认 5s)
}

// Client 聚合三个跨进程 client.
type Client struct {
	Engine   EngineClient
	Vulnsync VulnSyncClient
	LLMProxy LLMProxyClient
	closers  []func() error
}

// New 构造. 当前回 ErrNotImplemented stub (gRPC 实现后续 PR 替换).
func New(cfg Config) (*Client, error) {
	if !cfg.UseGRPC {
		return &Client{
			Engine:   inprocEngine{},
			Vulnsync: inprocVulnsync{},
			LLMProxy: inprocLLM{},
		}, nil
	}
	// TODO(A8): gRPC dial + 各 Client 工厂
	return nil, errors.New("client: gRPC mode not yet implemented (after A8)")
}

// Close 关闭所有 gRPC 连接.
func (c *Client) Close() error {
	var firstErr error
	for _, cl := range c.closers {
		if err := cl(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---- DTO ----

// KubeBaselineResult Engine 返回的基线扫描摘要.
type KubeBaselineResult struct {
	ClusterID  string
	TotalRules int
	Passed     int
	Failed     int
	StartedAt  time.Time
	FinishedAt time.Time
}

// Anomaly 异常事件 (Engine ML 输出).
type Anomaly struct {
	ID         string
	HostID     string
	Score      float64
	Reason     string
	DetectedAt time.Time
}

// Advisory VulnSync 输出的漏洞情报.
type Advisory struct {
	CVE         string
	Severity    string
	CVSS        float64
	Description string
	PublishedAt time.Time
	ModifiedAt  time.Time
}

// ChatRequest LLM 对话请求.
type ChatRequest struct {
	Messages []ChatMessage
	Model    string
	TenantID string
}

// ChatMessage 单轮消息.
type ChatMessage struct {
	Role    string // system / user / assistant
	Content string
}

// ChatResponse 应答.
type ChatResponse struct {
	Content      string
	InputTokens  int
	OutputTokens int
	Model        string
}

// ---- inproc stub (单进程跑时, 后续 PR 接 engine.* 直 call) ----

type inprocEngine struct{}

func (inprocEngine) KubeBaselineCheck(_ context.Context, _ string) (*KubeBaselineResult, error) {
	return nil, errors.New("inproc Engine: not yet wired (A8 后续 PR)")
}
func (inprocEngine) QueryAnomaly(_ context.Context, _ string, _ time.Duration) ([]Anomaly, error) {
	return nil, errors.New("inproc Engine: not yet wired (A8 后续 PR)")
}

type inprocVulnsync struct{}

func (inprocVulnsync) TriggerSync(_ context.Context, _ string) error {
	return errors.New("inproc Vulnsync: not yet wired (A8 后续 PR)")
}
func (inprocVulnsync) LookupAdvisory(_ context.Context, _ string) (*Advisory, error) {
	return nil, errors.New("inproc Vulnsync: not yet wired (A8 后续 PR)")
}

type inprocLLM struct{}

func (inprocLLM) Chat(_ context.Context, _ *ChatRequest) (*ChatResponse, error) {
	return nil, errors.New("inproc LLMProxy: not yet wired (A8 后续 PR)")
}
func (inprocLLM) SummarizeIncident(_ context.Context, _ string) (string, error) {
	return "", errors.New("inproc LLMProxy: not yet wired (A8 后续 PR)")
}
