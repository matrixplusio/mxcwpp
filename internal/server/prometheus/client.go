// Package prometheus 提供 Prometheus 查询客户端
package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// Client 是 Prometheus 查询客户端
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewClient 创建 Prometheus 查询客户端
// baseURL 是 Prometheus API 基础 URL，例如 "http://prometheus:9090"
func NewClient(baseURL string, timeout time.Duration, logger *zap.Logger) *Client {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

// QueryResult 是 Prometheus 查询结果
type QueryResult struct {
	Status string    `json:"status"`
	Data   QueryData `json:"data"`
}

// QueryData 是查询数据
type QueryData struct {
	ResultType string        `json:"resultType"`
	Result     []SampleValue `json:"result"`
}

// SampleValue 是样本值
type SampleValue struct {
	Metric map[string]string `json:"metric"`
	Value  []interface{}     `json:"value"` // [timestamp, value]
}

// RangeQueryResult 是范围查询结果
type RangeQueryResult struct {
	Status string         `json:"status"`
	Data   RangeQueryData `json:"data"`
}

// RangeQueryData 是范围查询数据
type RangeQueryData struct {
	ResultType string             `json:"resultType"`
	Result     []RangeSampleValue `json:"result"`
}

// RangeSampleValue 是范围样本值
type RangeSampleValue struct {
	Metric map[string]string `json:"metric"`
	Values [][]interface{}   `json:"values"` // [[timestamp, value], ...]
}

// QueryInstant 执行即时查询
// query 是 PromQL 查询语句
// time 是查询时间（可选，nil 表示当前时间）
func (c *Client) QueryInstant(ctx context.Context, query string, queryTime *time.Time) (*QueryResult, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/query")
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	q := u.Query()
	q.Set("query", query)
	if queryTime != nil {
		q.Set("time", queryTime.Format(time.RFC3339))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("执行请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Prometheus API 返回错误: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result QueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.Status != "success" {
		return nil, fmt.Errorf("Prometheus 查询失败: status=%s", result.Status)
	}

	return &result, nil
}

// QueryRange 执行范围查询
// query 是 PromQL 查询语句
// start 是开始时间
// end 是结束时间
// step 是步长（例如 "15s", "1m", "1h"）
func (c *Client) QueryRange(ctx context.Context, query string, start, end time.Time, step string) (*RangeQueryResult, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/query_range")
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	q := u.Query()
	q.Set("query", query)
	q.Set("start", start.Format(time.RFC3339))
	q.Set("end", end.Format(time.RFC3339))
	q.Set("step", step)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("执行请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Prometheus API 返回错误: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result RangeQueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.Status != "success" {
		return nil, fmt.Errorf("Prometheus 查询失败: status=%s", result.Status)
	}

	return &result, nil
}

// GetMetricValue 获取单个指标的当前值
// metricName 是指标名称，例如 "mxsec_host_cpu_usage"
// labels 是标签过滤，例如 map[string]string{"host_id": "host-uuid"}
// 返回指标值，如果不存在则返回 nil
func (c *Client) GetMetricValue(ctx context.Context, metricName string, labels map[string]string) (*float64, error) {
	// 构建 PromQL 查询
	query := metricName
	if len(labels) > 0 {
		labelFilters := ""
		for k, v := range labels {
			if labelFilters != "" {
				labelFilters += ","
			}
			labelFilters += fmt.Sprintf(`%s="%s"`, k, v)
		}
		query = fmt.Sprintf("%s{%s}", metricName, labelFilters)
	}

	result, err := c.QueryInstant(ctx, query, nil)
	if err != nil {
		return nil, err
	}

	if len(result.Data.Result) == 0 {
		return nil, nil // 指标不存在
	}

	// 取第一个结果的值
	value := result.Data.Result[0].Value[1]
	switch v := value.(type) {
	case string:
		var f float64
		if _, err := fmt.Sscanf(v, "%f", &f); err != nil {
			return nil, fmt.Errorf("解析指标值失败: %w", err)
		}
		return &f, nil
	case float64:
		return &v, nil
	default:
		return nil, fmt.Errorf("不支持的指标值类型: %T", value)
	}
}

// GetMetricRange 获取指标的时间范围值
// metricName 是指标名称
// labels 是标签过滤
// start 是开始时间
// end 是结束时间
// step 是步长
// 返回时间序列数据
func (c *Client) GetMetricRange(ctx context.Context, metricName string, labels map[string]string, start, end time.Time, step string) ([]TimeSeriesPoint, error) {
	// 构建 PromQL 查询
	query := metricName
	if len(labels) > 0 {
		labelFilters := ""
		for k, v := range labels {
			if labelFilters != "" {
				labelFilters += ","
			}
			labelFilters += fmt.Sprintf(`%s="%s"`, k, v)
		}
		query = fmt.Sprintf("%s{%s}", metricName, labelFilters)
	}

	result, err := c.QueryRange(ctx, query, start, end, step)
	if err != nil {
		return nil, err
	}

	if len(result.Data.Result) == 0 {
		return []TimeSeriesPoint{}, nil
	}

	// 取第一个结果的时间序列
	values := result.Data.Result[0].Values
	points := make([]TimeSeriesPoint, 0, len(values))
	for _, v := range values {
		if len(v) < 2 {
			continue
		}

		timestamp, ok := v[0].(float64)
		if !ok {
			continue
		}

		var value float64
		switch val := v[1].(type) {
		case string:
			if _, err := fmt.Sscanf(val, "%f", &value); err != nil {
				c.logger.Warn("解析时间序列值失败", zap.Error(err), zap.Any("value", val))
				continue
			}
		case float64:
			value = val
		default:
			c.logger.Warn("不支持的时间序列值类型", zap.Any("type", val))
			continue
		}

		points = append(points, TimeSeriesPoint{
			Timestamp: time.Unix(int64(timestamp), 0),
			Value:     value,
		})
	}

	return points, nil
}

// TimeSeriesPoint 是时间序列数据点
type TimeSeriesPoint struct {
	Timestamp time.Time
	Value     float64
}
