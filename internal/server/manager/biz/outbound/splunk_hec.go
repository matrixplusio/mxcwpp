package outbound

// Splunk HEC (HTTP Event Collector) connector (P2-3 第 4 种).
//
// 协议参考: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
// 端点格式: POST https://splunk.local:8088/services/collector/event
// Header:   Authorization: Splunk <token>
// Body:     {"time": <epoch>, "host": "...", "source": "...", "sourcetype": "...", "event": {...}}
//
// 一行一个 event, 多 event 合 batch 优化吞吐。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SplunkHECConnector 推送到 Splunk HEC。
type SplunkHECConnector struct {
	url        string
	token      string
	index      string
	sourcetype string
	client     *http.Client
	logger     *zap.Logger
}

// NewSplunkHECConnector 构造。
func NewSplunkHECConnector(url, token, index, sourcetype string, logger *zap.Logger) *SplunkHECConnector {
	if logger == nil {
		logger = zap.NewNop()
	}
	if sourcetype == "" {
		sourcetype = "mxcwpp:alert"
	}
	return &SplunkHECConnector{
		url:        url,
		token:      token,
		index:      index,
		sourcetype: sourcetype,
		client:     &http.Client{Timeout: 10 * time.Second},
		logger:     logger,
	}
}

// Name 名字。
func (c *SplunkHECConnector) Name() string { return "splunk_hec" }

// Send 把 Event 包装成 HEC 格式 + POST。
func (c *SplunkHECConnector) Send(ctx context.Context, ev *Event) error {
	hecEvent := map[string]any{
		"time":       ev.Timestamp.Unix(),
		"host":       ev.HostName,
		"source":     "mxcwpp",
		"sourcetype": c.sourcetype,
		"event":      ev,
	}
	if c.index != "" {
		hecEvent["index"] = c.index
	}
	body, _ := json.Marshal(hecEvent)
	req, err := http.NewRequestWithContext(ctx, "POST", c.url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk hec do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("splunk hec status %d", resp.StatusCode)
	}
	return nil
}

// Close 释放 http client。
func (c *SplunkHECConnector) Close() error {
	c.client.CloseIdleConnections()
	return nil
}
