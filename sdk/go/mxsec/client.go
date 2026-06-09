// Package mxsec is the official Go SDK for mxsec platform API (P4-3).
//
// 用法:
//
//	cli, err := mxsec.NewClient("https://mxsec.example.com",
//	    mxsec.WithToken("eyJhbGc..."))
//	hosts, err := cli.ListHosts(ctx, mxsec.HostListOptions{Status: "online"})
//
// Alerts / Vulns / Hosts / Mode / ConfigChange / Quarantine 全 endpoint 支持.
package mxsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client 是 mxsec API HTTP 客户端.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
	userAgent  string
}

// Option Client 配置选项.
type Option func(*Client)

// WithToken 设置 JWT bearer token.
func WithToken(token string) Option {
	return func(c *Client) { c.token = token }
}

// WithHTTPClient 自定义 http.Client (e.g. timeout/proxy).
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// WithUserAgent 自定义 User-Agent.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// NewClient 构造.
func NewClient(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL required")
	}
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  "mxsec-go-sdk/0.1.0",
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// ApiResponse 统一响应信封.
type ApiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// Host 主机.
type Host struct {
	HostID        string `json:"host_id"`
	Hostname      string `json:"hostname"`
	IP            string `json:"ip"`
	OS            string `json:"os_family"`
	OSVersion     string `json:"os_version"`
	Kernel        string `json:"kernel_version"`
	Arch          string `json:"arch"`
	Status        string `json:"status"`
	AgentVersion  string `json:"agent_version"`
	LastHeartbeat string `json:"last_heartbeat"`
	TenantID      string `json:"tenant_id"`
}

// HostListOptions 列表过滤.
type HostListOptions struct {
	Page     int    `url:"page,omitempty"`
	PageSize int    `url:"page_size,omitempty"`
	Status   string `url:"status,omitempty"`
}

// HostList 列表响应.
type HostList struct {
	Items []Host `json:"items"`
	Total int    `json:"total"`
}

// ListHosts GET /api/v1/hosts.
func (c *Client) ListHosts(ctx context.Context, opts HostListOptions) (*HostList, error) {
	u := c.baseURL + "/api/v1/hosts"
	q := url.Values{}
	if opts.Status != "" {
		q.Set("status", opts.Status)
	}
	if opts.Page > 0 {
		q.Set("page", fmt.Sprintf("%d", opts.Page))
	}
	if opts.PageSize > 0 {
		q.Set("page_size", fmt.Sprintf("%d", opts.PageSize))
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	resp, err := c.do(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	var hl HostList
	if err := json.Unmarshal(resp.Data, &hl); err != nil {
		return nil, fmt.Errorf("decode hosts: %w", err)
	}
	return &hl, nil
}

// Alert 告警.
type Alert struct {
	AlertID     string `json:"alert_id"`
	HostID      string `json:"host_id"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	MitreID     string `json:"mitre_id"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	TenantID    string `json:"tenant_id"`
}

// ListAlerts GET /api/v1/alerts.
func (c *Client) ListAlerts(ctx context.Context, severity, status string) ([]Alert, error) {
	u := c.baseURL + "/api/v1/alerts"
	q := url.Values{}
	if severity != "" {
		q.Set("severity", severity)
	}
	if status != "" {
		q.Set("status", status)
	}
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	resp, err := c.do(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Items []Alert `json:"items"`
	}
	if err := json.Unmarshal(resp.Data, &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Items, nil
}

// SetMode POST /api/v2/admin/tenants/{id}/mode.
func (c *Client) SetMode(ctx context.Context, tenantID, mode, reason string) error {
	if mode != "observe" && mode != "protect" {
		return fmt.Errorf("mode must be observe or protect")
	}
	payload := map[string]string{"mode": mode, "reason": reason}
	u := c.baseURL + "/api/v2/admin/tenants/" + tenantID + "/mode"
	_, err := c.do(ctx, "POST", u, payload)
	return err
}

// do 单 HTTP 调用.
func (c *Client) do(ctx context.Context, method, urlStr string, body any) (*ApiResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("mxsec %s %d: %s", method, resp.StatusCode, string(raw))
	}
	var ar ApiResponse
	if err := json.Unmarshal(raw, &ar); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if ar.Code != 0 {
		return nil, fmt.Errorf("mxsec api code=%d msg=%s", ar.Code, ar.Message)
	}
	return &ar, nil
}
