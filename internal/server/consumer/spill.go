package consumer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/IBM/sarama"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/consumer/writer"
)

// TopicCHSpill 转存写不进 ClickHouse 的行（加环境前缀后使用）。上线前手工建好并设保留策略，
// 不依赖自动建主题：broker 默认按分区 1GiB 删段，回放之前数据就可能没了。
const TopicCHSpill = "mxcwpp.consumer.ch-spill"

// ReplayGroup 回放工具使用的消费组，用它的提交位置计算还有多少待回放。
const ReplayGroup = "mxcwpp-ch-spill-replay"

// spillTimeout 一次转存的总时限。转存时持有刷盘锁，Kafka 卡住时不能拖住提交屏障与停机。
var spillTimeout = 30 * time.Second

// minSpillRetention 转存主题至少保留这么久，留出发现、修复与回放的时间。
const minSpillRetention = 7 * 24 * time.Hour

// KafkaSpiller 用同步生产者转存，等 ISR 确认后才返回：返回 nil 后这些行会从内存删除、
// 对应 offset 随之提交，用异步发送的话"已发出"并不等于"已落盘"。
type KafkaSpiller struct {
	client   sarama.Client
	producer sarama.SyncProducer
	topic    string
}

// NewKafkaSpiller 创建转存器，并检查转存主题存在且保留策略不会提前删数据。
func NewKafkaSpiller(cfg config.KafkaConfig) (*KafkaSpiller, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafka brokers 未配置")
	}
	topic := cfg.TopicPrefix + TopicCHSpill
	sc := sarama.NewConfig()
	sc.Producer.Return.Successes = true
	sc.Producer.Return.Errors = true
	sc.Producer.RequiredAcks = sarama.WaitForAll
	sc.Producer.Retry.Max = 3
	sc.Producer.Timeout = 10 * time.Second
	sc.Producer.MaxMessageBytes = 4 * 1024 * 1024
	sc.Producer.Compression = sarama.CompressionSnappy
	sc.Metadata.AllowAutoTopicCreation = false
	client, err := sarama.NewClient(cfg.Brokers, sc)
	if err != nil {
		return nil, fmt.Errorf("连接 Kafka 失败: %w", err)
	}
	if err := checkSpillTopic(client, topic); err != nil {
		_ = client.Close()
		return nil, err
	}
	p, err := sarama.NewSyncProducerFromClient(client)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("创建转存生产者失败: %w", err)
	}
	return &KafkaSpiller{client: client, producer: p, topic: topic}, nil
}

// checkSpillTopic 转存主题必须存在，且不按大小删数据、保留期足够长。
func checkSpillTopic(client sarama.Client, topic string) error {
	admin, err := sarama.NewClusterAdminFromClient(client)
	if err != nil {
		return fmt.Errorf("创建 Kafka 管理客户端失败: %w", err)
	}
	// 不关 admin：它与 client 共用连接，关它会把 client 一起关掉。
	entries, err := admin.DescribeConfig(sarama.ConfigResource{Type: sarama.TopicResource, Name: topic})
	if err != nil {
		return fmt.Errorf("读取转存主题 %s 配置失败（主题需上线前手工创建）: %w", topic, err)
	}
	cfg := map[string]string{}
	for _, e := range entries {
		cfg[e.Name] = e.Value
	}
	if v := cfg["retention.bytes"]; v != "-1" {
		return fmt.Errorf("转存主题 %s 的 retention.bytes=%s，会在回放前按大小删数据，须设为 -1", topic, v)
	}
	ms, err := strconv.ParseInt(cfg["retention.ms"], 10, 64)
	if err != nil || (ms >= 0 && time.Duration(ms)*time.Millisecond < minSpillRetention) {
		return fmt.Errorf("转存主题 %s 的 retention.ms=%s，短于 %s", topic, cfg["retention.ms"], minSpillRetention)
	}
	return nil
}

// Spill 实现 writer.Spiller。消息不带 key，按随机分区分散，不让一张表挤进同一个分区。
func (s *KafkaSpiller) Spill(records []writer.SpillRecord) error {
	msgs := make([]*sarama.ProducerMessage, 0, len(records))
	for _, r := range records {
		body, err := encodeSpillRecord(r)
		if err != nil {
			return err
		}
		msgs = append(msgs, &sarama.ProducerMessage{Topic: s.topic, Value: sarama.ByteEncoder(body)})
	}
	done := make(chan error, 1)
	go func() { done <- s.producer.SendMessages(msgs) }()
	select {
	case err := <-done:
		return err
	case <-time.After(spillTimeout):
		// 发送仍在后台进行，之后可能成功：调用方会整批重试，转存主题里可能多一份。
		return fmt.Errorf("转存超过 %s 未完成", spillTimeout)
	}
}

// encodeSpillRecord 序列化一条转存记录，不做 HTML 转义。json.Marshal 会对 RawMessage 的
// 内容重新转义，把 < > & 放大到 6 倍：写入方按字节装好的 1MB 记录会变成超过 Kafka 4MB
// 上限的消息，永远发不出去，进而让整个 consumer 停止提交 offset。
func encodeSpillRecord(r writer.SpillRecord) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// PendingReplay 转存主题里回放工具还没处理的记录数。
func (s *KafkaSpiller) PendingReplay() (int64, error) {
	return PendingReplay(s.client, s.topic, ReplayGroup)
}

// PendingReplay 按回放消费组的提交位置，计算转存主题里还没回放的记录数。
func PendingReplay(client sarama.Client, topic, group string) (int64, error) {
	if err := client.RefreshMetadata(topic); err != nil {
		return 0, err
	}
	parts, err := client.Partitions(topic)
	if err != nil {
		return 0, err
	}
	admin, err := sarama.NewClusterAdminFromClient(client)
	if err != nil {
		return 0, err
	}
	committed, err := admin.ListConsumerGroupOffsets(group, map[string][]int32{topic: parts})
	if err != nil {
		return 0, err
	}
	var pending int64
	for _, p := range parts {
		newest, err := client.GetOffset(topic, p, sarama.OffsetNewest)
		if err != nil {
			return 0, err
		}
		oldest, err := client.GetOffset(topic, p, sarama.OffsetOldest)
		if err != nil {
			return 0, err
		}
		from := oldest
		if b := committed.GetBlock(topic, p); b != nil && b.Offset > from {
			from = b.Offset
		}
		if newest > from {
			pending += newest - from
		}
	}
	return pending, nil
}

// Topic 转存主题全名。
func (s *KafkaSpiller) Topic() string { return s.topic }

// Close 关闭生产者与连接。须在写入器最终刷盘完成之后调用。
func (s *KafkaSpiller) Close() error {
	err := s.producer.Close()
	if cerr := s.client.Close(); err == nil {
		err = cerr
	}
	return err
}
