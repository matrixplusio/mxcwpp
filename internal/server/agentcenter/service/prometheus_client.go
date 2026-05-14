// Package service 提供 AgentCenter 业务逻辑
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// PrometheusClient Prometheus 远程写入客户端
type PrometheusClient struct {
	remoteWriteURL string
	pushgatewayURL string
	jobName        string
	timeout        time.Duration
	httpClient     *http.Client
	logger         *zap.Logger
}

// NewPrometheusClient 创建 Prometheus 客户端
func NewPrometheusClient(remoteWriteURL, pushgatewayURL, jobName string, timeout time.Duration, logger *zap.Logger) *PrometheusClient {
	return &PrometheusClient{
		remoteWriteURL: remoteWriteURL,
		pushgatewayURL: pushgatewayURL,
		jobName:        jobName,
		timeout:        timeout,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

// WriteMetrics 写入监控指标到 Prometheus
func (c *PrometheusClient) WriteMetrics(ctx context.Context, hostID string, metrics map[string]float64, timestamp time.Time) error {
	if c.pushgatewayURL != "" {
		return c.writeToPushgateway(ctx, hostID, metrics, timestamp)
	}
	if c.remoteWriteURL != "" {
		return c.writeToRemoteWrite(ctx, hostID, metrics, timestamp)
	}
	return fmt.Errorf("no Prometheus endpoint configured")
}

// writeToPushgateway 写入到 Pushgateway
func (c *PrometheusClient) writeToPushgateway(ctx context.Context, hostID string, metrics map[string]float64, timestamp time.Time) error {
	// Pushgateway 使用 Prometheus 文本格式
	var buf bytes.Buffer

	for name, value := range metrics {
		// Prometheus 指标格式：metric_name{labels} value timestamp
		metricLine := fmt.Sprintf("mxsec_host_%s{host_id=\"%s\"} %f %d\n",
			name, hostID, value, timestamp.UnixMilli())
		buf.WriteString(metricLine)
	}

	// Pushgateway API: POST /metrics/job/{job_name}/instance/{instance}
	url := fmt.Sprintf("%s/metrics/job/%s/instance/%s", c.pushgatewayURL, c.jobName, hostID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain; version=0.0.4")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pushgateway returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// writeToRemoteWrite 写入到 Prometheus Remote Write API
func (c *PrometheusClient) writeToRemoteWrite(ctx context.Context, hostID string, metrics map[string]float64, timestamp time.Time) error {
	// Prometheus Remote Write 使用 Protobuf 格式
	// 为了简化，我们使用 JSON 格式（需要 Prometheus 支持 JSON 格式的 Remote Write）
	// 或者使用 Prometheus 的 Go 客户端库

	// 这里使用简化的 JSON 格式（实际应该使用 Protobuf）
	type TimeSeries struct {
		Labels []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"labels"`
		Samples []struct {
			Value     float64 `json:"value"`
			Timestamp int64   `json:"timestamp"`
		} `json:"samples"`
	}

	var timeSeries []TimeSeries

	for name, value := range metrics {
		ts := TimeSeries{
			Labels: []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			}{
				{Name: "__name__", Value: fmt.Sprintf("mxsec_host_%s", name)},
				{Name: "host_id", Value: hostID},
			},
			Samples: []struct {
				Value     float64 `json:"value"`
				Timestamp int64   `json:"timestamp"`
			}{
				{Value: value, Timestamp: timestamp.UnixMilli()},
			},
		}
		timeSeries = append(timeSeries, ts)
	}

	payload := map[string]interface{}{
		"timeseries": timeSeries,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.remoteWriteURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remote write returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
