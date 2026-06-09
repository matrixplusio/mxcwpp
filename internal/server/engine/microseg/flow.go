// Package microseg 实现微隔离 (Microsegmentation) 流量观察 + 策略推荐 + Enforcement。
//
// 设计文档: ref/05-容器K8s.md §5 + ref/00 §3 C-9
//
// 三阶段路线:
//
//	Phase 1 (本 PR Sprint 3): 观察模式 - FlowCollector 收集 5min/5 元组聚合, 不下策略
//	Phase 2 (Sprint 4): 策略推荐 - 基于 7d 观察画像生成 NetworkPolicy 建议
//	Phase 3 (Sprint 5): Enforce - 下发 K8s NetworkPolicy / eBPF Cilium 规则
//
// 对标青藤零域 MSG (微隔离平台).
package microseg

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// FlowEvent 是单次 5min 5 元组流量聚合事件 (Agent eBPF cgroup_skb 上报)。
type FlowEvent struct {
	HostID     string `json:"host_id"`
	TenantID   string `json:"tenant_id"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	DstPort    int32  `json:"dst_port"`
	Protocol   string `json:"protocol"` // tcp/udp/sctp
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	PacketsIn  int64  `json:"packets_in"`
	PacketsOut int64  `json:"packets_out"`
	Direction  string `json:"direction"` // ingress/egress
	// 容器场景额外字段
	SrcNamespace string    `json:"src_namespace,omitempty"`
	SrcPodName   string    `json:"src_pod_name,omitempty"`
	SrcContainer string    `json:"src_container,omitempty"`
	DstNamespace string    `json:"dst_namespace,omitempty"`
	DstPodName   string    `json:"dst_pod_name,omitempty"`
	StartAt      time.Time `json:"start_at"`
	EndAt        time.Time `json:"end_at"`
}

// FlowKey 是流量聚合的 key (5 元组 + 容器命名空间维度)。
type FlowKey struct {
	TenantID     string
	SrcNamespace string
	SrcPodName   string
	DstNamespace string
	DstPodName   string
	DstPort      int32
	Protocol     string
}

// FlowAggregate 是单 (FlowKey, time_window) 内的累积统计。
type FlowAggregate struct {
	Key         FlowKey
	WindowStart time.Time
	WindowEnd   time.Time
	HitCount    int64
	TotalBytes  int64
}

// Collector 内存聚合 5min FlowEvent。
//
// Phase 1 目的: 周期性把聚合后的 FlowAggregate 推送到 Kafka mxsec.engine.feedback,
// Phase 2 拓扑/策略推荐时拉取分析。
type Collector struct {
	mu         sync.Mutex
	aggregates map[FlowKey]*FlowAggregate
	window     time.Duration
}

// NewCollector 构造。
func NewCollector(window time.Duration) *Collector {
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &Collector{
		aggregates: make(map[FlowKey]*FlowAggregate),
		window:     window,
	}
}

// Ingest 累积单条 FlowEvent。
func (c *Collector) Ingest(_ context.Context, ev FlowEvent) {
	key := FlowKey{
		TenantID:     ev.TenantID,
		SrcNamespace: ev.SrcNamespace,
		SrcPodName:   ev.SrcPodName,
		DstNamespace: ev.DstNamespace,
		DstPodName:   ev.DstPodName,
		DstPort:      ev.DstPort,
		Protocol:     ev.Protocol,
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	agg, ok := c.aggregates[key]
	if !ok {
		agg = &FlowAggregate{
			Key:         key,
			WindowStart: time.Now(),
			WindowEnd:   time.Now(),
		}
		c.aggregates[key] = agg
	}
	agg.HitCount++
	agg.TotalBytes += ev.BytesIn + ev.BytesOut
	agg.WindowEnd = time.Now()
}

// Flush 返回当前窗口的所有聚合并清空。
func (c *Collector) Flush() []*FlowAggregate {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*FlowAggregate, 0, len(c.aggregates))
	for _, a := range c.aggregates {
		out = append(out, a)
	}
	c.aggregates = make(map[FlowKey]*FlowAggregate)
	return out
}

// MarshalForKafka 把单条 aggregate 序列化为 Kafka 消息 body。
func (a *FlowAggregate) MarshalForKafka() ([]byte, error) {
	return json.Marshal(map[string]any{
		"tenant_id":     a.Key.TenantID,
		"src_namespace": a.Key.SrcNamespace,
		"src_pod_name":  a.Key.SrcPodName,
		"dst_namespace": a.Key.DstNamespace,
		"dst_pod_name":  a.Key.DstPodName,
		"dst_port":      a.Key.DstPort,
		"protocol":      a.Key.Protocol,
		"hit_count":     a.HitCount,
		"total_bytes":   a.TotalBytes,
		"window_start":  a.WindowStart,
		"window_end":    a.WindowEnd,
	})
}
