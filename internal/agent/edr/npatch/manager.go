// Package npatch — NPatch 双路径 manager (P3-K').
//
// 路径选择 (启动时 probe):
//
//	kernel 4.10+ → cgroup_skb eBPF (in-kernel 高效, 13 条规则)
//	kernel 3.10  → AF_PACKET v3 (CentOS 7 默认, 用户态 7 层匹配)
//	更老         → 不启用, log warn
//
// 用户态 7 层匹配复用 cgroup_skb 内的同套字符串模式 (在 user space 用 bytes.Index 替 BPF unroll).
package npatch

import (
	"context"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/npatch/afpacket"
	"github.com/matrixplusio/mxcwpp/internal/agent/edr/npatch/probe"
)

// Manager NPatch 双路径调度.
type Manager struct {
	logger  *zap.Logger
	backend probe.Backend

	// AF_PACKET v3 reader (仅 CentOS 7 默认 kernel 用)
	afReader *afpacket.Reader

	// hit counter 给 metrics 用
	hits    atomic.Uint64
	dropped atomic.Uint64

	stopOnce sync.Once
	stopCh   chan struct{}
}

// Config Manager 配置.
type Config struct {
	// Interface AF_PACKET v3 监听网卡 (默认 eth0)
	Interface string
	// Promisc AF_PACKET 混杂模式
	Promisc bool
}

// NewManager 构造 + 自动 probe + 启动对应路径.
func NewManager(cfg Config, logger *zap.Logger) (*Manager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg.Interface == "" {
		cfg.Interface = "eth0"
	}
	backend, err := probe.SelectBackend()
	if err != nil {
		return nil, err
	}
	kv, _ := probe.Kernel()
	m := &Manager{
		logger:  logger,
		backend: backend,
		stopCh:  make(chan struct{}),
	}
	switch backend {
	case probe.BackendCgroupSkb:
		logger.Info("NPatch backend: cgroup_skb eBPF (in-kernel, 高效)",
			zap.String("kernel", kv.String()))
		// 实际 BPF 加载由现有 npatch BPF 程序处理 (P0-2 fastpath已落)
	case probe.BackendAFPacket:
		logger.Info("NPatch backend: AF_PACKET v3 (CentOS 7 fallback)",
			zap.String("kernel", kv.String()),
			zap.Bool("centos7_default", probe.IsCentOS7Default()))
		if err := m.startAFPacket(cfg); err != nil {
			logger.Warn("AF_PACKET v3 启动失败, NPatch 降级",
				zap.Error(err))
		}
	default:
		logger.Warn("NPatch 不支持当前内核, 已禁用",
			zap.String("kernel", kv.String()))
	}
	return m, nil
}

// Backend 当前路径.
func (m *Manager) Backend() probe.Backend { return m.backend }

// Stats 返回累计命中 / 丢包.
func (m *Manager) Stats() (hits, dropped uint64) {
	if m.afReader != nil {
		read, drop := m.afReader.Stats()
		return m.hits.Load() + read, m.dropped.Load() + drop
	}
	return m.hits.Load(), m.dropped.Load()
}

// Close 优雅关闭.
func (m *Manager) Close() error {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		if m.afReader != nil {
			_ = m.afReader.Close()
		}
	})
	return nil
}

// startAFPacket 启动 AF_PACKET v3 读循环 + 用户态模式匹配.
func (m *Manager) startAFPacket(cfg Config) error {
	r, err := afpacket.NewReader(afpacket.Config{
		Interface: cfg.Interface,
		BlockSize: 1 << 20,
		NumBlocks: 64,
		FrameSize: 2048,
		Promisc:   cfg.Promisc,
		Filter:    afpacket.BuildHTTPFilter(),
	})
	if err != nil {
		return err
	}
	m.afReader = r
	go m.afPacketLoop(context.Background())
	return nil
}

// afPacketLoop 用户态消费 + 7 层匹配 (replaces in-kernel cgroup_skb unroll scan).
func (m *Manager) afPacketLoop(ctx context.Context) {
	patterns := userspacePatterns()
	for {
		select {
		case <-m.stopCh:
			return
		case pkt, ok := <-m.afReader.Packets():
			if !ok {
				return
			}
			for _, p := range patterns {
				if containsAtIndex(pkt.Data, p.needle) {
					m.hits.Add(1)
					m.logger.Warn("NPatch AF_PACKET hit",
						zap.String("rule", p.rule),
						zap.Int("pkt_len", len(pkt.Data)))
					break
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// userspacePatterns 与 BPF NPatch 13 条规则等价的用户态字符串模式.
//
// (cgroup_skb 中的 unroll 32 次 substring scan → 用户态 bytes.Index, 性能等价).
func userspacePatterns() []userPattern {
	return []userPattern{
		// Log4j
		{rule: "log4j_jndi", needle: []byte("${jndi:")},
		// Spring4Shell
		{rule: "spring4shell", needle: []byte("class.module.classLoader")},
		// Shellshock
		{rule: "shellshock", needle: []byte("() { :;}")},
		// Confluence OGNL
		{rule: "confluence_ognl", needle: []byte("freemarker.template")},
		// Spring Actuator
		{rule: "spring_actuator", needle: []byte("/actuator/env")},
		// PHPUnit eval-stdin
		{rule: "phpunit", needle: []byte("phpunit/src/Util/PHP/eval-stdin.php")},
		// ImageMagick
		{rule: "imagemagick", needle: []byte("mvg:")},
		// Bitbucket envinj
		{rule: "bitbucket_envinj", needle: []byte("/repos/")},
		// Atlassian OAuth
		{rule: "atlassian_oauth", needle: []byte("/setup/setupadministrator.action")},
		// OFBiz XML-RPC
		{rule: "ofbiz_xmlrpc", needle: []byte("CommonsBeanutils")},
		// GitLab ExifTool
		{rule: "gitlab_exiftool", needle: []byte("ANTa")},
		// Jenkins Script Console
		{rule: "jenkins_script", needle: []byte("Runtime.getRuntime")},
		// Nginx Lua
		{rule: "nginx_lua", needle: []byte("loadstring(")},
	}
}

type userPattern struct {
	rule   string
	needle []byte
}

// containsAtIndex 简单子串搜.
func containsAtIndex(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
