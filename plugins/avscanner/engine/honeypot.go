// Package engine 实现 av-scanner 插件核心逻辑:
//   - honeypot 诱饵投放 + fanotify 监控 (反勒索)
//   - 文件扫描 (ClamAV 后续接入,本 PR 仅脚手架)
//   - YARA 规则匹配 (后续 PR)
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DecoyKind 是诱饵类型。
type DecoyKind string

const (
	DecoyDOCX DecoyKind = "docx"
	DecoyXLSX DecoyKind = "xlsx"
	DecoyPNG  DecoyKind = "png"
	DecoyCSV  DecoyKind = "csv"
	DecoyPDF  DecoyKind = "pdf"
	DecoyTXT  DecoyKind = "txt"
)

// DecoyFile 是单个诱饵文件元信息。
type DecoyFile struct {
	Path       string
	Kind       DecoyKind
	DeployedAt time.Time
	Size       int64
}

// HoneypotConfig 诱饵投放配置。
type HoneypotConfig struct {
	// 目标目录 (会在每个目录投放一组诱饵)
	TargetDirs []string
	// 单次投放的诱饵种类 (默认 6 类)
	Kinds []DecoyKind
	// 文件前缀/后缀混淆 (避免命名特征)
	NameSeed string
}

// DefaultHoneypotConfig 返回默认配置 (Linux 主机典型勒索目标目录)。
func DefaultHoneypotConfig() HoneypotConfig {
	return HoneypotConfig{
		TargetDirs: []string{
			"/root",
			"/home", // 投到 /home/<user>/Documents 子树
			"/var/backups",
			"/srv",
		},
		Kinds: []DecoyKind{
			DecoyDOCX, DecoyXLSX, DecoyPNG, DecoyCSV, DecoyPDF, DecoyTXT,
		},
		NameSeed: "important",
	}
}

// HoneypotManager 管理诱饵生命周期 + fanotify 监控。
type HoneypotManager struct {
	cfg    HoneypotConfig
	logger *zap.Logger

	mu      sync.RWMutex
	decoys  map[string]*DecoyFile // path -> meta
	watcher *decoyWatcher         // 平台相关 (Linux: inotify; 其他: noop)

	triggerCh chan DecoyTrigger // 命中事件输出
}

// DecoyTrigger 是单次诱饵触发事件 (上报给 Agent 主进程 → Server)。
type DecoyTrigger struct {
	DecoyPath     string
	DecoyKind     DecoyKind
	Operation     string // open / write / rename / unlink
	TriggeringPID int32
	TriggeringExe string
	TriggeringUID int32
	Timestamp     time.Time
}

// NewHoneypotManager 构造。
func NewHoneypotManager(cfg HoneypotConfig, logger *zap.Logger) *HoneypotManager {
	if logger == nil {
		logger = zap.NewNop()
	}
	if len(cfg.Kinds) == 0 {
		cfg = DefaultHoneypotConfig()
	}
	return &HoneypotManager{
		cfg:       cfg,
		logger:    logger,
		decoys:    make(map[string]*DecoyFile),
		watcher:   newDecoyWatcher(logger), // 平台相关构造
		triggerCh: make(chan DecoyTrigger, 64),
	}
}

// Deploy 在目标目录投放诱饵。
//
// 幂等: 已存在的诱饵跳过 (按 path 索引)。
func (m *HoneypotManager) Deploy() error {
	for _, dir := range m.cfg.TargetDirs {
		if dir == "/home" {
			// /home 特殊处理: 枚举一级子目录 (用户家目录)
			entries, err := os.ReadDir(dir)
			if err != nil {
				m.logger.Warn("read /home failed", zap.Error(err))
				continue
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				m.deployToDir(filepath.Join(dir, e.Name(), "Documents"))
			}
			continue
		}
		m.deployToDir(dir)
	}
	return nil
}

func (m *HoneypotManager) deployToDir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// 目录不可创建 (权限/只读) 跳过, 不算致命
		m.logger.Debug("mkdir for decoy skip", zap.String("dir", dir), zap.Error(err))
		return
	}
	for _, kind := range m.cfg.Kinds {
		path := m.decoyPath(dir, kind)
		m.mu.RLock()
		_, exists := m.decoys[path]
		m.mu.RUnlock()
		if exists {
			continue
		}
		size, err := writeDecoyFile(path, kind)
		if err != nil {
			m.logger.Warn("write decoy failed", zap.String("path", path), zap.Error(err))
			continue
		}
		m.mu.Lock()
		m.decoys[path] = &DecoyFile{
			Path:       path,
			Kind:       kind,
			DeployedAt: time.Now(),
			Size:       size,
		}
		m.mu.Unlock()
		// 加入 watcher
		if err := m.watcher.Watch(path); err != nil {
			m.logger.Warn("watch decoy failed", zap.String("path", path), zap.Error(err))
		}
		m.logger.Info("decoy deployed",
			zap.String("path", path), zap.String("kind", string(kind)))
	}
}

func (m *HoneypotManager) decoyPath(dir string, kind DecoyKind) string {
	// 隐蔽命名: .mxcwpp_decoy_<seed>.<ext> 太显眼
	// 选择业务感强的命名: salary_2025.<ext> / contracts_q4.<ext>
	switch kind {
	case DecoyDOCX:
		return filepath.Join(dir, "contracts_q4.docx")
	case DecoyXLSX:
		return filepath.Join(dir, "salary_2025.xlsx")
	case DecoyPNG:
		return filepath.Join(dir, "passport_scan.png")
	case DecoyCSV:
		return filepath.Join(dir, "customers_export.csv")
	case DecoyPDF:
		return filepath.Join(dir, "tax_return.pdf")
	case DecoyTXT:
		return filepath.Join(dir, ".credentials.txt")
	}
	return filepath.Join(dir, fmt.Sprintf("decoy_%s.bin", kind))
}

// Triggers 暴露命中事件 channel。
func (m *HoneypotManager) Triggers() <-chan DecoyTrigger { return m.triggerCh }

// Run 启动 watcher 主循环, 阻塞直到 ctx 取消。
func (m *HoneypotManager) Run(stop <-chan struct{}) {
	events := m.watcher.Events()
	for {
		select {
		case <-stop:
			_ = m.watcher.Close()
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			m.mu.RLock()
			meta, isDecoy := m.decoys[ev.Path]
			m.mu.RUnlock()
			if !isDecoy {
				continue
			}
			trigger := DecoyTrigger{
				DecoyPath:     ev.Path,
				DecoyKind:     meta.Kind,
				Operation:     ev.Operation,
				TriggeringPID: ev.PID,
				TriggeringExe: ev.Exe,
				TriggeringUID: ev.UID,
				Timestamp:     time.Now(),
			}
			select {
			case m.triggerCh <- trigger:
			default:
				m.logger.Warn("decoy trigger queue full, drop",
					zap.String("path", ev.Path))
			}
		}
	}
}

// Decoys 返回当前已投放的诱饵 snapshot (test/inspection 用)。
func (m *HoneypotManager) Decoys() []DecoyFile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DecoyFile, 0, len(m.decoys))
	for _, d := range m.decoys {
		out = append(out, *d)
	}
	return out
}

// writeDecoyFile 写一个看起来像真业务文件的诱饵。
//
// 内容混入随机字节 + 文件类型 magic header,避免被勒索快速跳过。
// 返回最终文件 size。
func writeDecoyFile(path string, kind DecoyKind) (int64, error) {
	header := decoyHeader(kind)
	// 8KB padding 让诱饵看起来"有价值"
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte((i*37 + 11) % 256)
	}
	content := append(header, body...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return 0, fmt.Errorf("write decoy %s: %w", path, err)
	}
	return int64(len(content)), nil
}

// decoyHeader 返回各文件类型的 magic header,通过简单类型识别。
func decoyHeader(kind DecoyKind) []byte {
	switch kind {
	case DecoyDOCX, DecoyXLSX:
		return []byte{0x50, 0x4B, 0x03, 0x04} // ZIP (Office Open XML)
	case DecoyPNG:
		return []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	case DecoyPDF:
		return []byte("%PDF-1.7\n")
	case DecoyCSV:
		return []byte("id,name,email,phone,salary\n")
	case DecoyTXT:
		return []byte("DB_PASS=\nAPI_TOKEN=\n")
	}
	return nil
}
