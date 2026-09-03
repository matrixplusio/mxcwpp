package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAIConfig 是 OpenAI / OpenAI-Compatible (DashScope/DeepSeek/Kimi/Ollama/vLLM) 驱动配置。
type OpenAIConfig struct {
	Name     string   // 注册名,如 openai-gpt-4o-mini / dashscope-qwen-turbo
	BaseURL  string   // https://api.openai.com/v1 / 兼容端点
	APIKey   string   // 留空时不发 Authorization 头 (Ollama 本地场景)
	Models   []string // 支持的模型清单
	Provider string   // 元数据: openai / dashscope / deepseek / kimi / ollama / vllm
	Timeout  time.Duration
}

// OpenAIProvider 实现 Provider interface。
// 所有 OpenAI-Compatible 厂商 (千问/DeepSeek/Kimi/Ollama/vLLM) 共用该 driver,
// 通过 BaseURL + APIKey 区分。
type OpenAIProvider struct {
	cfg    OpenAIConfig
	client *http.Client
}

// NewOpenAI 构造 OpenAI / OpenAI-Compatible provider。
func NewOpenAI(cfg OpenAIConfig) *OpenAIProvider {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.Provider == "" {
		cfg.Provider = "openai"
	}
	return &OpenAIProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (p *OpenAIProvider) Name() string              { return p.cfg.Name }
func (p *OpenAIProvider) Type() string              { return p.cfg.Provider }
func (p *OpenAIProvider) SupportedModels() []string { return p.cfg.Models }

// Complete 调用 OpenAI Chat Completion API。
func (p *OpenAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if !p.supports(req.Model) {
		return nil, fmt.Errorf("%w: %s", ErrModelNotSupported, req.Model)
	}

	body := map[string]any{
		"model":    req.Model,
		"messages": p.buildMessages(req),
	}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}

	jb, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jb))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("openai api error %d: %s", resp.StatusCode, string(rb))
	}

	var raw struct {
		Choices []struct {
			Message      struct{ Content string } `json:"message"`
			FinishReason string                   `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(rb, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	if len(raw.Choices) == 0 {
		return nil, fmt.Errorf("openai api: no choices in response")
	}
	return &CompletionResponse{
		Content:      raw.Choices[0].Message.Content,
		Model:        raw.Model,
		FinishReason: raw.Choices[0].FinishReason,
		TokensIn:     raw.Usage.PromptTokens,
		TokensOut:    raw.Usage.CompletionTokens,
		Provider:     p.cfg.Provider,
	}, nil
}

// Embed 调用 OpenAI Embeddings API (text-embedding-3-small 等)。
func (p *OpenAIProvider) Embed(ctx context.Context, text string, model string) ([]float32, error) {
	body := map[string]any{
		"model": model,
		"input": text,
	}
	jb, _ := json.Marshal(body)

	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/embeddings"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jb))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	}
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()

	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("openai embed error %d: %s", resp.StatusCode, string(rb))
	}
	var raw struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rb, &raw); err != nil {
		return nil, err
	}
	if len(raw.Data) == 0 {
		return nil, fmt.Errorf("openai embed: empty data")
	}
	return raw.Data[0].Embedding, nil
}

// HealthCheck 调用 /models 列表接口探活。
func (p *OpenAIProvider) HealthCheck(ctx context.Context) error {
	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if p.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("%w: status %d", ErrProviderUnavailable, resp.StatusCode)
	}
	return nil
}

func (p *OpenAIProvider) supports(model string) bool {
	if len(p.cfg.Models) == 0 {
		return true // 未限定时接受任意模型 (Ollama 本地场景)
	}
	for _, m := range p.cfg.Models {
		if m == model {
			return true
		}
	}
	return false
}

func (p *OpenAIProvider) buildMessages(req CompletionRequest) []map[string]string {
	msgs := make([]map[string]string, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, map[string]string{"role": "system", "content": req.System})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]string{"role": m.Role, "content": m.Content})
	}
	return msgs
}

// 编译期断言
var _ Provider = (*OpenAIProvider)(nil)
