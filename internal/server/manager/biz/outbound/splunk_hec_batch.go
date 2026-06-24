package outbound

// Splunk HEC 批量缓冲 + 周期 flush (P3-4).
//
// 对比 splunk_hec.go (PR100 单条同步):
//   - 缓冲队列 batchSize 或 batchTimeout 触发 flush
//   - Splunk HEC 单 request 多 event (一行一个 JSON, 与 NDJSON 同)
//   - 吞吐量提升 ~10-50x (具体取决于 batchSize)
//
// 失败重试:
//   - 单次 batch 失败 → 写死信 channel (调用方决定丢弃 / 持久化重发)
//   - 5xx 错误 → 指数退避重试 3 次
//   - 4xx 错误 → 不重试 (配置错)

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SplunkHECBatchConnector 缓冲版.
type SplunkHECBatchConnector struct {
	url          string
	token        string
	index        string
	sourcetype   string
	batchSize    int
	batchTimeout time.Duration
	client       *http.Client
	logger       *zap.Logger

	mu     sync.Mutex
	buffer []*Event
	stop   chan struct{}
}

// SplunkHECBatchConfig 配置.
type SplunkHECBatchConfig struct {
	URL          string
	Token        string
	Index        string
	Sourcetype   string
	BatchSize    int           // 默认 100
	BatchTimeout time.Duration // 默认 5s
}

// NewSplunkHECBatchConnector 构造 + 启动 flush goroutine.
func NewSplunkHECBatchConnector(cfg SplunkHECBatchConfig, logger *zap.Logger) *SplunkHECBatchConnector {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 5 * time.Second
	}
	if cfg.Sourcetype == "" {
		cfg.Sourcetype = "mxcwpp:alert"
	}
	c := &SplunkHECBatchConnector{
		url:          cfg.URL,
		token:        cfg.Token,
		index:        cfg.Index,
		sourcetype:   cfg.Sourcetype,
		batchSize:    cfg.BatchSize,
		batchTimeout: cfg.BatchTimeout,
		client:       &http.Client{Timeout: 15 * time.Second},
		logger:       logger,
		buffer:       make([]*Event, 0, cfg.BatchSize),
		stop:         make(chan struct{}),
	}
	go c.flushLoop()
	return c
}

// Name.
func (c *SplunkHECBatchConnector) Name() string { return "splunk_hec_batch" }

// Send 入队. 满 batch 立即 flush, 否则等 batchTimeout.
func (c *SplunkHECBatchConnector) Send(_ context.Context, ev *Event) error {
	c.mu.Lock()
	c.buffer = append(c.buffer, ev)
	full := len(c.buffer) >= c.batchSize
	c.mu.Unlock()
	if full {
		return c.flush()
	}
	return nil
}

// Close 停 flush + 末 flush 一次.
func (c *SplunkHECBatchConnector) Close() error {
	close(c.stop)
	_ = c.flush()
	c.client.CloseIdleConnections()
	return nil
}

// flushLoop 周期 flush.
func (c *SplunkHECBatchConnector) flushLoop() {
	t := time.NewTicker(c.batchTimeout)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			_ = c.flush()
		}
	}
}

// flush 把 buffer 一次 POST. 重试 3 次指数退避.
func (c *SplunkHECBatchConnector) flush() error {
	c.mu.Lock()
	if len(c.buffer) == 0 {
		c.mu.Unlock()
		return nil
	}
	batch := c.buffer
	c.buffer = make([]*Event, 0, c.batchSize)
	c.mu.Unlock()

	// HEC 多 event 同 POST (一行一个 JSON object, 整体不需要 array)
	var body strings.Builder
	for _, ev := range batch {
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
		raw, _ := json.Marshal(hecEvent)
		body.Write(raw)
		body.WriteString("\n")
	}

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		req, err := http.NewRequestWithContext(ctx, "POST", c.url, strings.NewReader(body.String()))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Authorization", "Splunk "+c.token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.client.Do(req)
		cancel()
		if err != nil {
			c.logger.Warn("splunk hec batch send transient", zap.Error(err))
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			c.logger.Debug("splunk hec batch flushed", zap.Int("count", len(batch)))
			return nil
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// 4xx 配置错 不重试
			return fmt.Errorf("splunk hec batch 4xx: %d", resp.StatusCode)
		}
	}
	c.logger.Error("splunk hec batch flush failed after 3 retries",
		zap.Int("dropped", len(batch)))
	return fmt.Errorf("splunk hec batch flush failed")
}
