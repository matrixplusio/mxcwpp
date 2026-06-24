package outbound

// Elastic Bulk connector (P2-3 第 5 种).
//
// 协议参考: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
// 端点格式: POST https://elastic.local:9200/_bulk
// Body 每两行一组 (NDJSON):
//
//	{"index": {"_index": "mxcwpp-alerts-YYYY.MM.dd"}}
//	{"@timestamp": "...", "severity": "...", ...}
//
// 单条优化吞吐: 后续 PR 加 batch 缓冲 + 周期 flush。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ElasticBulkConnector 推送到 Elasticsearch _bulk。
type ElasticBulkConnector struct {
	url           string // base URL (e.g. https://es:9200)
	indexPrefix   string // 例 "mxcwpp-alerts"
	authHeader    string // 例 "Basic xxxx" or "ApiKey xxxx"
	rolloverDaily bool
	client        *http.Client
	logger        *zap.Logger
}

// NewElasticBulkConnector 构造。
func NewElasticBulkConnector(baseURL, indexPrefix, authHeader string, rolloverDaily bool, logger *zap.Logger) *ElasticBulkConnector {
	if logger == nil {
		logger = zap.NewNop()
	}
	if indexPrefix == "" {
		indexPrefix = "mxcwpp-alerts"
	}
	return &ElasticBulkConnector{
		url:           strings.TrimRight(baseURL, "/") + "/_bulk",
		indexPrefix:   indexPrefix,
		authHeader:    authHeader,
		rolloverDaily: rolloverDaily,
		client:        &http.Client{Timeout: 15 * time.Second},
		logger:        logger,
	}
}

// Name 名字。
func (c *ElasticBulkConnector) Name() string { return "elastic_bulk" }

// Send 单 event _bulk POST。
func (c *ElasticBulkConnector) Send(ctx context.Context, ev *Event) error {
	idx := c.indexPrefix
	if c.rolloverDaily {
		idx = c.indexPrefix + "-" + ev.Timestamp.UTC().Format("2006.01.02")
	}
	meta := map[string]any{
		"index": map[string]string{"_index": idx},
	}
	metaJSON, _ := json.Marshal(meta)
	// Elastic 期望 @timestamp 字段
	doc := map[string]any{
		"@timestamp":  ev.Timestamp.UTC().Format(time.RFC3339Nano),
		"id":          ev.ID,
		"tenant_id":   ev.TenantID,
		"host_id":     ev.HostID,
		"host_name":   ev.HostName,
		"severity":    ev.Severity,
		"category":    ev.Category,
		"rule_id":     ev.RuleID,
		"title":       ev.Title,
		"description": ev.Description,
		"mitre_id":    ev.MitreID,
		"source":      ev.Source,
		"fields":      ev.Fields,
	}
	docJSON, _ := json.Marshal(doc)
	body := string(metaJSON) + "\n" + string(docJSON) + "\n"

	req, err := http.NewRequestWithContext(ctx, "POST", c.url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("elastic bulk do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("elastic bulk status %d", resp.StatusCode)
	}
	return nil
}

// Close 释放 http client。
func (c *ElasticBulkConnector) Close() error {
	c.client.CloseIdleConnections()
	return nil
}
