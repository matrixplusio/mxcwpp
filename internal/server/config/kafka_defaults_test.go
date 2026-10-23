package config

import "testing"

// 未配置时，生产者的单条上限必须是 4MB，与生产者自身的默认值一致。
// 这里曾默认成 1MB 并覆盖掉生产者的设置：资产多的主机单条消息可能超过 1MB，会在每个采集周期被丢弃。
func TestKafkaProducerMaxMessageBytesDefault(t *testing.T) {
	cfg := &Config{}
	setDefaults(cfg, false)
	if got, want := cfg.Kafka.Producer.MaxMessageBytes, 4*1024*1024; got != want {
		t.Errorf("默认 MaxMessageBytes=%d，期望 %d", got, want)
	}

	cfg = &Config{}
	cfg.Kafka.Producer.MaxMessageBytes = 2 * 1024 * 1024
	setDefaults(cfg, false)
	if got := cfg.Kafka.Producer.MaxMessageBytes; got != 2*1024*1024 {
		t.Errorf("显式配置不应被默认值覆盖，得 %d", got)
	}
}
