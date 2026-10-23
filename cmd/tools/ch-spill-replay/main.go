// ch-spill-replay 把 consumer 转存到 Kafka 的、写不进 ClickHouse 的行写回 ClickHouse。
//
// consumer 在 ClickHouse 持续不可用（或某些行取值不合表结构）时，把这些行转存到
// <topic_prefix>mxcwpp.consumer.ch-spill，并告警 MxCwppConsumerCHSpilled。修好之后跑本工具：
//
//	ch-spill-replay -config /etc/mxcwpp/server.yaml            # 先看有多少待回放
//	ch-spill-replay -config /etc/mxcwpp/server.yaml -apply     # 真正写入
//
// 用独立的消费组，从最早未提交处读起；一条记录写入成功才提交它的 offset，失败即停，
// 重跑会从失败的那条继续。转存时若部分重复（转存重试），回放会在 ClickHouse 里多出重复行。
// 取值不合表结构的行仍会被拒收：默认遇到即停、不提交，先补表结构再回放；
// 确认要放弃这些行时加 -skip-rejected。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/writer"
	"github.com/matrixplusio/mxcwpp/internal/server/database"
)

func main() {
	configPath := flag.String("config", "", "consumer 使用的配置文件")
	apply := flag.Bool("apply", false, "真正写入 ClickHouse；不加只统计")
	group := flag.String("group", consumer.ReplayGroup, "回放用的消费组")
	idle := flag.Duration("idle", 30*time.Second, "所有分区都这么久没有新记录就结束")
	skipRejected := flag.Bool("skip-rejected", false, "有行被拒收时仍提交（这些行就此放弃）")
	flag.Parse()
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "需要 -config")
		os.Exit(2)
	}

	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("读取配置失败", zap.Error(err))
	}
	topic := cfg.Kafka.TopicPrefix + consumer.TopicCHSpill

	var w *writer.ClickHouseWriter
	if *apply {
		conn, err := database.InitClickHouse(cfg.ClickHouse, logger)
		if err != nil || conn == nil {
			logger.Fatal("连接 ClickHouse 失败", zap.Error(err))
		}
		defer func() { _ = database.CloseClickHouse() }()
		w = writer.NewClickHouseWriter(conn, 5000, time.Hour, logger)
		defer w.Close()
	}

	sc := sarama.NewConfig()
	sc.Consumer.Offsets.Initial = sarama.OffsetOldest
	sc.Consumer.Offsets.AutoCommit.Enable = false
	cg, err := sarama.NewConsumerGroup(cfg.Kafka.Brokers, *group, sc)
	if err != nil {
		logger.Fatal("创建消费组失败", zap.Error(err))
	}
	defer func() { _ = cg.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	h := &handler{w: w, apply: *apply, skipRejected: *skipRejected, cancel: cancel, stats: map[string]*stat{}}
	h.touch()
	// 空闲按全局算：分区各自计时的话，一个没有数据的分区先超时就会把整个回放取消。
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, h.lastActivity.Load())) > *idle {
					cancel()
					return
				}
			}
		}
	}()
	if err := cg.Consume(ctx, []string{topic}, h); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("消费出错", zap.Error(err))
	}

	mode := "统计（未写入，加 -apply 写入）"
	if *apply {
		mode = "已写入"
	}
	fmt.Printf("主题 %s，%s：\n", topic, mode)
	for table, s := range h.stats {
		fmt.Printf("  %-14s 记录 %d  行 %d  写入 %d  拒收 %d\n", table, s.records, s.rows, s.written, s.rejected)
	}
	if client, err := sarama.NewClient(cfg.Kafka.Brokers, sarama.NewConfig()); err == nil {
		if n, err := consumer.PendingReplay(client, topic, *group); err == nil {
			fmt.Printf("消费组 %s 还有 %d 条未提交（统计模式不提交，数字不变属正常）\n", *group, n)
		}
		_ = client.Close()
	}
	if h.err != nil {
		fmt.Printf("在一条记录上停止：%v（重跑会从这条继续）\n", h.err)
		os.Exit(1)
	}
}

type stat struct{ records, rows, written, rejected int }

// handler 的 ConsumeClaim 按分区并发调用，stats 与 err 由 mu 保护。
type handler struct {
	mu           sync.Mutex
	w            *writer.ClickHouseWriter
	apply        bool
	skipRejected bool
	cancel       context.CancelFunc
	stats        map[string]*stat
	err          error
	lastActivity atomic.Int64
}

func (h *handler) touch() { h.lastActivity.Store(time.Now().UnixNano()) }

func (h *handler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *handler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

func (h *handler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case <-sess.Context().Done():
			return nil
		case msg, ok := <-claim.Messages():
			if !ok {
				return nil
			}
			h.touch()
			var rec writer.SpillRecord
			if err := json.Unmarshal(msg.Value, &rec); err != nil {
				h.fail(fmt.Errorf("offset %d 解析失败: %w", msg.Offset, err))
				return nil
			}
			var rows []json.RawMessage
			_ = json.Unmarshal(rec.Rows, &rows)
			h.mu.Lock()
			s := h.stats[rec.Table]
			if s == nil {
				s = &stat{}
				h.stats[rec.Table] = s
			}
			s.records++
			s.rows += len(rows)
			h.mu.Unlock()
			if !h.apply {
				continue // 只统计：不提交 offset，之后 -apply 还能读到
			}
			written, rejected, err := h.w.ReplaySpill(rec)
			if err != nil {
				h.fail(fmt.Errorf("partition %d offset %d: %w", msg.Partition, msg.Offset, err))
				return nil
			}
			h.mu.Lock()
			s.written += written
			s.rejected += rejected
			h.mu.Unlock()
			if rejected > 0 && !h.skipRejected {
				// 好行已写入，但这条不提交：重跑会再写一次好行（重复），换来被拒收的行不被悄悄放弃。
				h.fail(fmt.Errorf("partition %d offset %d 有 %d 行被拒收，先补表结构再回放，或加 -skip-rejected 放弃这些行",
					msg.Partition, msg.Offset, rejected))
				return nil
			}
			sess.MarkMessage(msg, "")
			sess.Commit()
		}
	}
}

func (h *handler) fail(err error) {
	h.mu.Lock()
	if h.err == nil {
		h.err = err
	}
	h.mu.Unlock()
	h.cancel()
}
