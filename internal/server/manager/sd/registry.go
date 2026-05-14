// Package sd 实现 Manager 内嵌的服务发现模块
// 负责 AgentCenter 实例的注册、心跳维护、主动健康探测和路由选择
package sd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// probeInterval 主动探测间隔
	probeInterval = 10 * time.Second
	// probeTimeout 单次探测超时
	probeTimeout = 3 * time.Second
	// unhealthyThreshold 连续失败次数阈值，超过则标记下线
	unhealthyThreshold = 3
	// heartbeatTTL AC 心跳超时（超过则认为宕机，不等待探测结果）
	heartbeatTTL = 60 * time.Second
	// sdPubSubChannel 跨 Manager 副本同步 AC 状态变更的 Pub/Sub 频道
	sdPubSubChannel = "ac:sd:changed"
	// sdSyncInterval 兜底全量同步间隔（防止 Pub/Sub 断线期间的遗漏）
	sdSyncInterval = 30 * time.Second
	// sdSubscribeRetry Pub/Sub 断线后重连等待时间
	sdSubscribeRetry = 3 * time.Second
)

// ACInstance 表示一个 AgentCenter 实例
type ACInstance struct {
	ID           string    `json:"id"`         // 实例唯一 ID（hostname 或配置的 instance_id）
	GRPCAddr     string    `json:"grpc_addr"`  // gRPC 地址（Agent 连接用）
	HTTPAddr     string    `json:"http_addr"`  // HTTP 管理地址（Manager 调用用）
	ConnCount    int64     `json:"conn_count"` // 当前在线 Agent 数（由心跳上报）
	Healthy      bool      `json:"healthy"`    // 是否健康
	RegisteredAt time.Time `json:"registered_at"`
	LastSeen     time.Time `json:"last_seen"` // 最近心跳时间

	failCount int32 // 连续探测失败次数（原子操作）
}

// Registry 管理所有 AC 实例，提供注册/注销/探测/选择能力
type Registry struct {
	mu          sync.RWMutex
	instances   map[string]*ACInstance
	logger      *zap.Logger
	httpClient  *http.Client
	redisClient *redis.Client // 可选，多 Manager 实例间同步 AC 状态
}

// NewRegistry 创建 Registry 并启动后台探测
func NewRegistry(logger *zap.Logger) *Registry {
	r := &Registry{
		instances:  make(map[string]*ACInstance),
		logger:     logger,
		httpClient: &http.Client{Timeout: probeTimeout},
	}
	return r
}

// SetRedisClient 注入 Redis 客户端，启用多 Manager 实例间 AC 状态同步
func (r *Registry) SetRedisClient(rc *redis.Client) {
	r.mu.Lock()
	r.redisClient = rc
	r.mu.Unlock()
}

// LoadFromRedis 从 Redis 全量加载所有 AC 实例到本地内存
// 在 Manager 启动时调用，用于恢复重启前的注册状态
func (r *Registry) LoadFromRedis() {
	if r.redisClient == nil {
		return
	}
	data, err := r.redisClient.HGetAll(context.Background(), "ac:instances").Result()
	if err != nil {
		r.logger.Warn("从 Redis 加载 AC 实例列表失败", zap.Error(err))
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, raw := range data {
		var inst ACInstance
		if err := json.Unmarshal([]byte(raw), &inst); err == nil {
			_, exists := r.instances[id]
			r.instances[id] = &inst
			if !exists {
				r.logger.Info("从 Redis 恢复 AC 实例", zap.String("id", id),
					zap.String("http_addr", inst.HTTPAddr),
					zap.Bool("healthy", inst.Healthy),
				)
			}
		}
	}
}

// loadFromRedis 从 Redis 加载单个 AC 实例（调用方持锁）
func (r *Registry) loadFromRedis(id string) *ACInstance {
	if r.redisClient == nil {
		return nil
	}
	data, err := r.redisClient.HGet(context.Background(), "ac:instances", id).Bytes()
	if err != nil {
		return nil
	}
	var inst ACInstance
	if err := json.Unmarshal(data, &inst); err != nil {
		return nil
	}
	return &inst
}

// syncToRedis 将 AC 实例状态写入 Redis hash，并发布变更通知
// key: ac:instances，field: instanceID，value: JSON
func (r *Registry) syncToRedis(inst *ACInstance) {
	if r.redisClient == nil {
		return
	}
	data, err := json.Marshal(inst)
	if err != nil {
		r.logger.Warn("序列化 AC 实例失败，跳过 Redis 同步", zap.String("id", inst.ID), zap.Error(err))
		return
	}
	ctx := context.Background()
	pipe := r.redisClient.Pipeline()
	pipe.HSet(ctx, "ac:instances", inst.ID, data)
	pipe.Expire(ctx, "ac:instances", 120*time.Second)
	// 发布变更通知，其他 Manager 副本订阅后立即感知（< 100ms）
	pipe.Publish(ctx, sdPubSubChannel, "upd:"+inst.ID)
	if _, err := pipe.Exec(ctx); err != nil {
		r.logger.Warn("同步 AC 状态到 Redis 失败", zap.String("id", inst.ID), zap.Error(err))
	}
}

// removeFromRedis 从 Redis hash 中删除 AC 实例并发布注销通知
func (r *Registry) removeFromRedis(id string) {
	if r.redisClient == nil {
		return
	}
	ctx := context.Background()
	pipe := r.redisClient.Pipeline()
	pipe.HDel(ctx, "ac:instances", id)
	pipe.Publish(ctx, sdPubSubChannel, "del:"+id)
	if _, err := pipe.Exec(ctx); err != nil {
		r.logger.Warn("从 Redis 删除 AC 实例失败", zap.String("id", id), zap.Error(err))
	}
}

// Start 启动后台主动探测 goroutine（需要在 ctx 取消时退出）
func (r *Registry) Start(ctx context.Context) {
	go r.probeLoop(ctx)
	if r.redisClient != nil {
		go r.subscriberLoop(ctx) // Pub/Sub 事件驱动，< 100ms 感知
		go r.redisSyncLoop(ctx)  // 30s 全量兜底，防止 Pub/Sub 断线期间遗漏
	}
}

// subscriberLoop 带重连的 Redis Pub/Sub 订阅主循环
func (r *Registry) subscriberLoop(ctx context.Context) {
	for {
		if err := r.runSubscriber(ctx); err != nil {
			// ctx 取消时退出，否则等待后重连
			if ctx.Err() != nil {
				return
			}
			r.logger.Warn("Redis Pub/Sub 断线，等待重连", zap.Error(err), zap.Duration("retry", sdSubscribeRetry))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sdSubscribeRetry):
		}
	}
}

// runSubscriber 订阅 ac:sd:changed 并处理消息，返回时表示连接断开
func (r *Registry) runSubscriber(ctx context.Context) error {
	sub := r.redisClient.Subscribe(ctx, sdPubSubChannel)
	defer sub.Close()

	// 等待订阅确认
	if _, err := sub.Receive(ctx); err != nil {
		return err
	}
	r.logger.Info("Redis Pub/Sub 订阅成功", zap.String("channel", sdPubSubChannel))

	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-ch:
			if !ok {
				return fmt.Errorf("Pub/Sub channel closed")
			}
			r.handleSDMessage(msg.Payload)
		}
	}
}

// handleSDMessage 处理来自其他 Manager 副本的 SD 变更通知
// payload 格式：upd:{id} 或 del:{id}
func (r *Registry) handleSDMessage(payload string) {
	if id, ok := strings.CutPrefix(payload, "upd:"); ok {
		inst := r.loadFromRedis(id)
		if inst == nil {
			return
		}
		r.mu.Lock()
		r.instances[id] = inst
		r.mu.Unlock()
		r.logger.Debug("Pub/Sub 同步 AC 实例更新", zap.String("id", id))
	} else if id, ok := strings.CutPrefix(payload, "del:"); ok {
		r.mu.Lock()
		delete(r.instances, id)
		r.mu.Unlock()
		r.logger.Info("Pub/Sub 同步 AC 实例注销", zap.String("id", id))
	}
}

// redisSyncLoop 每 sdSyncInterval 全量同步一次，兜底 Pub/Sub 断线期间的遗漏
func (r *Registry) redisSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(sdSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.LoadFromRedis()
		}
	}
}

// Register 注册或更新一个 AC 实例
func (r *Registry) Register(id, grpcAddr, httpAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if inst, ok := r.instances[id]; ok {
		// 更新已有实例
		inst.GRPCAddr = grpcAddr
		inst.HTTPAddr = httpAddr
		inst.LastSeen = time.Now()
		inst.Healthy = true
		atomic.StoreInt32(&inst.failCount, 0)
		r.logger.Info("AC 实例更新注册", zap.String("id", id), zap.String("http_addr", httpAddr))
		r.syncToRedis(inst)
		return
	}

	newInst := &ACInstance{
		ID:           id,
		GRPCAddr:     grpcAddr,
		HTTPAddr:     httpAddr,
		Healthy:      true,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}
	r.instances[id] = newInst
	r.logger.Info("AC 实例注册成功",
		zap.String("id", id),
		zap.String("grpc_addr", grpcAddr),
		zap.String("http_addr", httpAddr),
	)
	r.syncToRedis(newInst)
}

// Heartbeat 更新 AC 实例心跳和连接数
func (r *Registry) Heartbeat(id string, connCount int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	inst, ok := r.instances[id]
	if !ok {
		// 本实例内存中没有，尝试从 Redis 恢复（另一个 Manager 副本注册的）
		inst = r.loadFromRedis(id)
		if inst == nil {
			return fmt.Errorf("AC 实例未注册: %s", id)
		}
		r.instances[id] = inst
		r.logger.Info("从 Redis 恢复 AC 实例（跨副本心跳）", zap.String("id", id))
	}
	inst.ConnCount = connCount
	inst.LastSeen = time.Now()
	// 心跳到达说明实例存活，重置失败计数
	atomic.StoreInt32(&inst.failCount, 0)
	if !inst.Healthy {
		inst.Healthy = true
		r.logger.Info("AC 实例通过心跳恢复健康", zap.String("id", id))
	}
	r.syncToRedis(inst)
	return nil
}

// Deregister 注销 AC 实例
func (r *Registry) Deregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.instances, id)
	r.logger.Info("AC 实例注销", zap.String("id", id))
	r.removeFromRedis(id)
}

// ListHealthy 返回所有健康 AC 实例的快照（只读副本）
func (r *Registry) ListHealthy() []*ACInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ACInstance, 0, len(r.instances))
	for _, inst := range r.instances {
		if inst.Healthy {
			// 返回副本，避免外部修改
			cp := *inst
			result = append(result, &cp)
		}
	}
	return result
}

// GetByID 返回指定 AC 实例的健康快照
func (r *Registry) GetByID(id string) *ACInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()

	inst, ok := r.instances[id]
	if !ok || !inst.Healthy {
		return nil
	}

	cp := *inst
	return &cp
}

// ListAll 返回所有 AC 实例快照（包括不健康的）
func (r *Registry) ListAll() []*ACInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ACInstance, 0, len(r.instances))
	for _, inst := range r.instances {
		cp := *inst
		result = append(result, &cp)
	}
	return result
}

// PickLeastConn 使用 power-of-two-choices 算法从健康 AC 中选出连接数最少的实例
// 随机选 2 个候选，返回连接数更少的那个
func (r *Registry) PickLeastConn() *ACInstance {
	healthy := r.ListHealthy()
	if len(healthy) == 0 {
		return nil
	}
	if len(healthy) == 1 {
		return healthy[0]
	}

	// power-of-two-choices：选前两个（已由 map 遍历提供随机性）
	a, b := healthy[0], healthy[1]
	if b.ConnCount < a.ConnCount {
		return b
	}
	return a
}

// probeLoop 每 probeInterval 探测一次所有 AC 实例
func (r *Registry) probeLoop(ctx context.Context) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.probeAll()
		}
	}
}

// probeAll 并发探测所有实例
func (r *Registry) probeAll() {
	r.mu.RLock()
	instances := make([]*ACInstance, 0, len(r.instances))
	for _, inst := range r.instances {
		instances = append(instances, inst)
	}
	r.mu.RUnlock()

	for _, inst := range instances {
		go r.probeOne(inst)
	}
}

// probeOne 探测单个 AC 实例的 /health 端点
func (r *Registry) probeOne(inst *ACInstance) {
	// 先检查心跳是否超时（不等探测结果直接标记下线）
	r.mu.RLock()
	lastSeen := inst.LastSeen
	id := inst.ID
	httpAddr := inst.HTTPAddr
	r.mu.RUnlock()

	if time.Since(lastSeen) > heartbeatTTL {
		r.markUnhealthy(id, "心跳超时")
		return
	}

	url := fmt.Sprintf("http://%s/health", httpAddr)
	resp, err := r.httpClient.Get(url)
	if err != nil {
		fails := atomic.AddInt32(&inst.failCount, 1)
		r.logger.Warn("AC 健康探测失败",
			zap.String("id", id),
			zap.String("url", url),
			zap.Int32("fail_count", fails),
			zap.Error(err),
		)
		if fails >= unhealthyThreshold {
			r.markUnhealthy(id, fmt.Sprintf("连续 %d 次探测失败", fails))
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fails := atomic.AddInt32(&inst.failCount, 1)
		if fails >= unhealthyThreshold {
			r.markUnhealthy(id, fmt.Sprintf("探测返回 %d", resp.StatusCode))
		}
		return
	}

	// 解析 conn count（可选，用于负载均衡精度）
	var body struct {
		OnlineConn int64 `json:"online_connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
		r.mu.Lock()
		if cur, ok := r.instances[id]; ok {
			cur.ConnCount = body.OnlineConn
		}
		r.mu.Unlock()
	}

	// 探测成功，重置失败计数
	atomic.StoreInt32(&inst.failCount, 0)
	r.mu.Lock()
	if cur, ok := r.instances[id]; ok && !cur.Healthy {
		cur.Healthy = true
		r.logger.Info("AC 实例探测恢复健康", zap.String("id", id))
		r.syncToRedis(cur)
	}
	r.mu.Unlock()
}

// markUnhealthy 标记 AC 实例为不健康并记录日志
func (r *Registry) markUnhealthy(id, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	inst, ok := r.instances[id]
	if !ok || !inst.Healthy {
		return
	}
	inst.Healthy = false
	r.logger.Error("AC 实例标记为不健康",
		zap.String("id", id),
		zap.String("reason", reason),
	)
	r.syncToRedis(inst)
}
