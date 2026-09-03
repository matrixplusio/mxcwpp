// dlq-replay 把死信队列里的消息重新投回原 Topic，交回正常消费链路处理。
//
// 消费失败的消息会被转入 {topic}.dlq 保底，指标与告警也已就位，但此前没有任何手段
// 把它们捞回来——数据留在 DLQ 里等于仍然缺失，只是缺得有记录。本工具补上这一段。
//
// 刻意做成运维手动执行而非自动重放：DLQ 里既有"下游临时故障"这种重放即可恢复的消息，
// 也有"字段非法/解析不了"这种重放多少次都会再次失败的毒消息。自动重放会让后者
// 在队列间无限循环并淹没正常流量，因此重放必须由人在确认根因已修复后发起。
//
// 用法:
//
//	dlq-replay -config deploy/config/server.yaml -topic mxcwpp.agent.ebpf          # 预演
//	dlq-replay -config deploy/config/server.yaml -topic mxcwpp.agent.ebpf -apply   # 真重放
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/IBM/sarama"

	"github.com/matrixplusio/mxcwpp/internal/server/common/kafka"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

// replayGroupID 固定消费组：重跑本工具会从上次停下的位置继续，不会把已重放过的再放一遍。
const replayGroupID = "mxcwpp-dlq-replay"

type options struct {
	configPath  string
	brokers     string
	topicPrefix string
	topic       string
	max         int
	maxRetry    int
	idle        time.Duration
	apply       bool
}

func main() {
	var opt options
	flag.StringVar(&opt.configPath, "config", "", "server.yaml 路径（用于读取 kafka.brokers 与 topic_prefix）")
	flag.StringVar(&opt.brokers, "brokers", "", "Kafka broker 列表，逗号分隔（覆盖 -config）")
	flag.StringVar(&opt.topicPrefix, "topic-prefix", "", "Topic 前缀（覆盖 -config）")
	flag.StringVar(&opt.topic, "topic", "", "源 Topic 名，如 mxcwpp.agent.ebpf（工具读取其 .dlq）")
	flag.IntVar(&opt.max, "max", 1000, "本次最多重放多少条")
	flag.IntVar(&opt.maxRetry, "max-retry", 3, "RetryCount 达到该值的消息视为毒消息，跳过不再重放")
	flag.DurationVar(&opt.idle, "idle", 5*time.Second, "多久读不到新消息即认为 DLQ 已排空并退出")
	flag.BoolVar(&opt.apply, "apply", false, "真正重放。默认只预演，不投递也不推进位点")
	flag.Parse()

	if err := run(opt); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func run(opt options) error {
	brokers, prefix, err := resolveKafka(opt)
	if err != nil {
		return err
	}
	if strings.TrimSpace(opt.topic) == "" {
		return errors.New("必须用 -topic 指定源 Topic")
	}
	if opt.max <= 0 {
		return errors.New("-max 必须为正数")
	}

	sourceTopic := prefix + opt.topic
	dlqTopic := kafka.DLQTopic(sourceTopic)

	mode := "预演（不投递、不推进位点）"
	if opt.apply {
		mode = "重放"
	}
	fmt.Printf("模式: %s\nDLQ Topic: %s\n目标 Topic: %s\nbrokers: %v\n\n",
		mode, dlqTopic, sourceTopic, brokers)

	// 同步生产者：必须确认每条投递成功后才推进位点，否则"重放了但没投出去"会二次丢失。
	// 常规链路用异步生产者是为了吞吐，这里正确性优先。
	prodCfg := sarama.NewConfig()
	prodCfg.Version = sarama.V2_6_0_0
	prodCfg.Producer.Return.Successes = true
	prodCfg.Producer.RequiredAcks = sarama.WaitForAll
	prodCfg.Producer.Retry.Max = 3
	producer, err := sarama.NewSyncProducer(brokers, prodCfg)
	if err != nil {
		return fmt.Errorf("创建生产者失败: %w", err)
	}
	defer func() { _ = producer.Close() }()

	consCfg := sarama.NewConfig()
	consCfg.Version = sarama.V2_6_0_0
	consCfg.Consumer.Offsets.Initial = sarama.OffsetOldest
	consCfg.Consumer.Return.Errors = true
	// 位点手动提交：只有确认投递成功的消息才推进，中途中断不会跳过未重放的消息。
	consCfg.Consumer.Offsets.AutoCommit.Enable = false
	group, err := sarama.NewConsumerGroup(brokers, replayGroupID, consCfg)
	if err != nil {
		return fmt.Errorf("创建消费组失败: %w", err)
	}
	defer func() { _ = group.Close() }()

	h := &replayHandler{opt: opt, producer: producer, sourceTopic: sourceTopic}
	h.lastMsg.Store(time.Now())

	ctx, cancel := signalContext()
	defer cancel()

	// 空闲即退出：DLQ 是有限集合，排空后不该一直挂着等新消息。
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if h.reachedLimit() || time.Since(h.lastSeen()) > opt.idle {
					cancel()
					return
				}
			}
		}
	}()

	for ctx.Err() == nil {
		if err := group.Consume(ctx, []string{dlqTopic}, h); err != nil {
			if errors.Is(err, sarama.ErrClosedConsumerGroup) || ctx.Err() != nil {
				break
			}
			return fmt.Errorf("消费 DLQ 失败: %w", err)
		}
	}
	<-done

	h.report(opt.apply)
	return nil
}

// resolveKafka 解析 broker 与 topic 前缀：命令行优先，其次配置文件。
func resolveKafka(opt options) ([]string, string, error) {
	prefix := opt.topicPrefix
	if b := strings.TrimSpace(opt.brokers); b != "" {
		return strings.Split(b, ","), prefix, nil
	}
	if strings.TrimSpace(opt.configPath) == "" {
		return nil, "", errors.New("必须提供 -config 或 -brokers")
	}
	cfg, err := config.Load(opt.configPath)
	if err != nil {
		return nil, "", fmt.Errorf("加载配置失败: %w", err)
	}
	if len(cfg.Kafka.Brokers) == 0 {
		return nil, "", errors.New("配置中 kafka.brokers 为空")
	}
	if prefix == "" {
		prefix = cfg.Kafka.TopicPrefix
	}
	return cfg.Kafka.Brokers, prefix, nil
}

// replayHandler 逐条处理 DLQ 消息。
type replayHandler struct {
	opt         options
	producer    sarama.SyncProducer
	sourceTopic string

	mu         sync.Mutex
	replayed   int
	poison     int
	undecodabl int
	reasons    map[string]int

	lastMsg atomicTime
}

func (h *replayHandler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *replayHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

func (h *replayHandler) reachedLimit() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.replayed >= h.opt.max
}

func (h *replayHandler) lastSeen() time.Time { return h.lastMsg.Load() }

func (h *replayHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for msg := range claim.Messages() {
		h.lastMsg.Store(time.Now())
		if h.reachedLimit() {
			return nil
		}

		var dlq kafka.DLQMessage
		if err := json.Unmarshal(msg.Value, &dlq); err != nil || dlq.Original == nil {
			// 解析不了的条目不重放，但仍推进位点，否则本工具会卡在同一条上反复读取。
			// 原始记录仍留在 DLQ Topic 里（Kafka 按保留期留存），不会因此被销毁。
			h.count(&h.undecodabl, "DLQ 记录无法解析")
			if h.opt.apply {
				session.MarkMessage(msg, "")
			}
			continue
		}

		if dlq.RetryCount >= h.opt.maxRetry {
			// 毒消息：重放多少次都会再失败，继续放只会污染正常流量。
			h.count(&h.poison, fmt.Sprintf("重试已达 %d 次: %s", dlq.RetryCount, truncate(dlq.Error)))
			if h.opt.apply {
				session.MarkMessage(msg, "")
			}
			continue
		}

		if !h.opt.apply {
			// 预演不投递也不推进位点，真跑时会重放同一批消息。
			h.count(&h.replayed, truncate(dlq.Error))
			continue
		}

		body, err := json.Marshal(dlq.Original)
		if err != nil {
			h.count(&h.undecodabl, "原始消息序列化失败")
			session.MarkMessage(msg, "")
			continue
		}
		if _, _, err := h.producer.SendMessage(&sarama.ProducerMessage{
			Topic: h.sourceTopic,
			Key:   sarama.StringEncoder(dlq.Original.AgentID),
			Value: sarama.ByteEncoder(body),
		}); err != nil {
			// 投递失败就不推进位点：这条消息下次还会被读到，不会因为工具中途出错而丢。
			return fmt.Errorf("重放投递失败（位点未推进，可重跑）: %w", err)
		}
		h.count(&h.replayed, truncate(dlq.Error))
		session.MarkMessage(msg, "")
		session.Commit()
	}
	return nil
}

func (h *replayHandler) count(counter *int, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	*counter++
	if h.reasons == nil {
		h.reasons = make(map[string]int)
	}
	h.reasons[reason]++
}

func (h *replayHandler) report(applied bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	verb := "待重放"
	if applied {
		verb = "已重放"
	}
	fmt.Printf("\n%s: %d 条\n", verb, h.replayed)
	fmt.Printf("跳过（毒消息，重试次数已达上限）: %d 条\n", h.poison)
	fmt.Printf("跳过（记录无法解析）: %d 条\n", h.undecodabl)
	if len(h.reasons) > 0 {
		fmt.Println("\n失败原因分布:")
		for reason, n := range h.reasons {
			fmt.Printf("  %6d  %s\n", n, reason)
		}
	}
	if !applied && h.replayed > 0 {
		fmt.Println("\n以上为预演结果，未投递任何消息。确认根因已修复后加 -apply 执行。")
	}
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(无错误信息)"
	}
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// signalContext 返回一个在 Ctrl-C / SIGTERM 时取消的 context，
// 让中断也走正常收尾：未确认投递的消息位点不推进，重跑即可继续。
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

// atomicTime 是并发安全的时间戳，用于判定 DLQ 是否已排空。
type atomicTime struct {
	mu sync.Mutex
	t  time.Time
}

func (a *atomicTime) Store(t time.Time) {
	a.mu.Lock()
	a.t = t
	a.mu.Unlock()
}

func (a *atomicTime) Load() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.t
}
