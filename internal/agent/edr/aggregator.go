//go:build linux

package edr

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

// aggregateWindow 聚合窗口大小：同一签名的事件在此窗口内合并为一条
const aggregateWindow = 10 * time.Second

// aggEntry 聚合缓冲条目
type aggEntry struct {
	event     *event.Event // 保留首次事件
	count     int          // 窗口内累计次数
	firstSeen time.Time    // 窗口起始时间
}

// eventAggregator 负责将高频重复事件在 Agent 端合并后再转发
// 聚合键 = event_type + 特征字段（进程: exe, 文件: file_path, 网络: remote_addr:remote_port）
// 安全事件（规则命中 / IOC 命中）不聚合，直接放行
type eventAggregator struct {
	mu      sync.Mutex
	buckets map[string]*aggEntry
	logger  *zap.Logger
}

// newEventAggregator 创建事件聚合器
func newEventAggregator(logger *zap.Logger) *eventAggregator {
	return &eventAggregator{
		buckets: make(map[string]*aggEntry),
		logger:  logger,
	}
}

// aggKey 根据事件类型生成聚合键
func aggKey(evt *event.Event) string {
	switch evt.DataType {
	case event.DataTypeProcess:
		return fmt.Sprintf("%s|%s", evt.EventType, evt.Fields["exe"])
	case event.DataTypeFile:
		return fmt.Sprintf("%s|%s", evt.EventType, evt.Fields["file_path"])
	case event.DataTypeNetwork:
		return fmt.Sprintf("%s|%s:%s", evt.EventType, evt.Fields["remote_addr"], evt.Fields["remote_port"])
	default:
		return string(evt.EventType)
	}
}

// shouldBypass 判断事件是否应跳过聚合直接转发（安全事件）
func shouldBypass(evt *event.Event) bool {
	if evt.Fields["agent_match"] == "true" {
		return true
	}
	if evt.Fields["ioc_match"] == "true" {
		return true
	}
	return false
}

// TryAggregate 尝试聚合事件
// 返回 true 表示事件被缓冲（不需要立即发送）
// 返回 false 表示事件应立即发送（安全事件 或 窗口首条）
func (a *eventAggregator) TryAggregate(evt *event.Event) bool {
	if shouldBypass(evt) {
		return false
	}

	key := aggKey(evt)

	a.mu.Lock()
	defer a.mu.Unlock()

	entry, exists := a.buckets[key]
	if !exists {
		// 窗口首条事件：缓存并放行（count=1 的事件不加 agg_count 字段）
		a.buckets[key] = &aggEntry{
			event:     evt,
			count:     1,
			firstSeen: time.Now(),
		}
		return false
	}

	// 窗口内重复事件：累加计数，不转发
	entry.count++
	return true
}

// Flush 刷出所有窗口已过期的聚合条目
// 返回需要发送的聚合摘要事件（count > 1 的）
func (a *eventAggregator) Flush() []*event.Event {
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	var flushed []*event.Event
	for key, entry := range a.buckets {
		if now.Sub(entry.firstSeen) < aggregateWindow {
			continue
		}

		// 窗口到期 → 如果 count > 1，生成聚合摘要事件
		if entry.count > 1 {
			summary := entry.event
			summary.SetField("agg_count", strconv.Itoa(entry.count))
			summary.SetField("agg_window", aggregateWindow.String())
			flushed = append(flushed, summary)
		}
		// count == 1 的已经在 TryAggregate 中直接放行，不需要再发

		delete(a.buckets, key)
	}

	return flushed
}

// FlushAll 强制刷出所有条目（用于关闭时）
func (a *eventAggregator) FlushAll() []*event.Event {
	a.mu.Lock()
	defer a.mu.Unlock()

	var flushed []*event.Event
	for key, entry := range a.buckets {
		if entry.count > 1 {
			summary := entry.event
			summary.SetField("agg_count", strconv.Itoa(entry.count))
			summary.SetField("agg_window", aggregateWindow.String())
			flushed = append(flushed, summary)
		}
		delete(a.buckets, key)
	}

	return flushed
}
