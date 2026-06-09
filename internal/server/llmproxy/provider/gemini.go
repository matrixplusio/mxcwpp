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

// GeminiConfig 是 Google Gemini API 配置。
type GeminiConfig struct {
	Name    string
	BaseURL string // https://generativelanguage.googleapis.com/v1
	APIKey  string
	Models  []string // gemini-1.5-flash / gemini-1.5-pro
	Timeout time.Duration
}

// GeminiProvider 实现 Provider interface (v1 generateContent endpoint)。
type GeminiProvider struct {
	cfg    GeminiConfig
	client *http.Client
}

// NewGemini 构造 Gemini provider。
func NewGemini(cfg GeminiConfig) *GeminiProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://generativelanguage.googleapis.com/v1"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &GeminiProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (p *GeminiProvider) Name() string              { return p.cfg.Name }
func (p *GeminiProvider) Type() string              { return "gemini" }
func (p *GeminiProvider) SupportedModels() []string { return p.cfg.Models }

func (p *GeminiProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if !p.supports(req.Model) {
		return nil, fmt.Errorf("%w: %s", ErrModelNotSupported, req.Model)
	}

	contents := buildGeminiContents(req)
	body := map[string]any{
		"contents": contents,
	}
	if req.Temperature > 0 || req.MaxTokens > 0 {
		gen := map[string]any{}
		if req.Temperature > 0 {
			gen["temperature"] = req.Temperature
		}
		if req.MaxTokens > 0 {
			gen["maxOutputTokens"] = req.MaxTokens
		}
		body["generationConfig"] = gen
	}
	if req.System != "" {
		body["systemInstruction"] = map[string]any{
			"parts": []map[string]string{{"text": req.System}},
		}
	}

	jb, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s",
		strings.TrimRight(p.cfg.BaseURL, "/"), req.Model, p.cfg.APIKey)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jb))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("gemini %d: %s", resp.StatusCode, string(rb))
	}

	var raw struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(rb, &raw); err != nil {
		return nil, err
	}
	if len(raw.Candidates) == 0 {
		return nil, fmt.Errorf("gemini: no candidates")
	}

	var content strings.Builder
	for _, part := range raw.Candidates[0].Content.Parts {
		content.WriteString(part.Text)
	}

	return &CompletionResponse{
		Content:      content.String(),
		Model:        req.Model,
		FinishReason: raw.Candidates[0].FinishReason,
		TokensIn:     raw.UsageMetadata.PromptTokenCount,
		TokensOut:    raw.UsageMetadata.CandidatesTokenCount,
		Provider:     "gemini",
	}, nil
}

// Embed Gemini Embedding API (text-embedding-004 等)。
func (p *GeminiProvider) Embed(ctx context.Context, text string, model string) ([]float32, error) {
	body := map[string]any{
		"model": "models/" + model,
		"content": map[string]any{
			"parts": []map[string]string{{"text": text}},
		},
	}
	jb, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/models/%s:embedContent?key=%s",
		strings.TrimRight(p.cfg.BaseURL, "/"), model, p.cfg.APIKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jb))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("gemini embed %d: %s", resp.StatusCode, string(rb))
	}
	var raw struct {
		Embedding struct {
			Values []float32 `json:"values"`
		} `json:"embedding"`
	}
	if err := json.Unmarshal(rb, &raw); err != nil {
		return nil, err
	}
	return raw.Embedding.Values, nil
}

func (p *GeminiProvider) HealthCheck(ctx context.Context) error {
	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/models?key=" + p.cfg.APIKey
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("gemini health: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("gemini health %d", resp.StatusCode)
	}
	return nil
}

func (p *GeminiProvider) supports(m string) bool {
	if len(p.cfg.Models) == 0 {
		return true
	}
	for _, s := range p.cfg.Models {
		if s == m {
			return true
		}
	}
	return false
}

func buildGeminiContents(req CompletionRequest) []map[string]any {
	out := make([]map[string]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		out = append(out, map[string]any{
			"role":  role,
			"parts": []map[string]string{{"text": m.Content}},
		})
	}
	return out
}

var _ Provider = (*GeminiProvider)(nil)
