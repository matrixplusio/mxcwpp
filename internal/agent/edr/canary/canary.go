// Package canary — 反勒索 / 反横移 蜜罐诱饵文件 (B9).
//
// 原理:
//
//	Agent 在常见目标目录 (用户家 / 共享 / 数据库 backup 路径) 放置看似真实的
//	诱饵文件 (银行账号.txt / 客户名单.xlsx / wallet.dat 等). 这些文件:
//
//	- 永不被合法业务读 / 写 (在白名单进程外的任何 read/write/rename/delete 都告警)
//	- sha256 已知 → 周期校验, hash 变 = 被加密/篡改 = 勒索软件命中
//	- 文件 setattr immutable → 攻击者 chattr 也是 IOC
//
// 工作流:
//  1. Deploy() 部署诱饵到目标路径, 注册 fanotify watch
//  2. 监听到 read/write/rename/delete 触发立刻产 critical alert
//  3. 周期 sha256 hash 校验 (5min), hash 变 = 篡改
//  4. UnDeploy() 清理
package canary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// File 单个诱饵.
type File struct {
	Path       string // 部署路径
	Hash       string // sha256 (Deploy 时计算)
	DeployedAt time.Time
}

// Event 诱饵触发事件.
type Event struct {
	Path      string
	Operation string // read / write / rename / delete / hash_changed
	PID       int32
	Comm      string
	Severity  string
	HashOld   string
	HashNew   string
	Time      time.Time
}

// Manager 诱饵管理器.
type Manager struct {
	logger   *zap.Logger
	interval time.Duration

	mu    sync.RWMutex
	files map[string]*File // path → File

	events chan Event
}

// NewManager 构造.
func NewManager(logger *zap.Logger) *Manager {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Manager{
		logger:   logger,
		interval: 5 * time.Minute,
		files:    map[string]*File{},
		events:   make(chan Event, 256),
	}
}

// Events 事件订阅.
func (m *Manager) Events() <-chan Event { return m.events }

// Deploy 部署一个诱饵.
//
// content 是写入文件的内容 (建议短文本伪装为银行账号 / 密码 / SSH key).
// 路径需要 Agent 写权限.
func (m *Manager) Deploy(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	hash := sha256Hex(content)
	m.mu.Lock()
	m.files[path] = &File{Path: path, Hash: hash, DeployedAt: time.Now()}
	m.mu.Unlock()
	m.logger.Info("canary deployed", zap.String("path", path), zap.String("hash", hash[:16]+"..."))
	return nil
}

// DeployBatch 一次性部署常见诱饵 (银行账号 / 客户名单 / wallet / SSH key 等).
func (m *Manager) DeployBatch(baseDir string) (int, error) {
	templates := map[string]string{
		"银行账号.txt":      "Bank: ICBC\nAccount: 6222024500001234567\nName: 张三\nBalance: 1,234,567.89",
		"客户名单.csv":      "name,phone,email,company\n王五,13800001111,wang@example.com,Foo Corp\n",
		"wallet.dat":    "Bitcoin Core wallet binary placeholder",
		"id_rsa":        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA[decoy-only-do-not-use]\n-----END OPENSSH PRIVATE KEY-----\n",
		"password.kdbx": "KeePass 2.x decoy database (canary)\n",
		"backup.sql":    "-- PostgreSQL backup decoy\n-- Generated 2026-06-07\n",
	}
	n := 0
	for name, content := range templates {
		p := filepath.Join(baseDir, name)
		if err := m.Deploy(p, []byte(content)); err == nil {
			n++
		} else {
			m.logger.Warn("canary deploy failed", zap.String("path", p), zap.Error(err))
		}
	}
	return n, nil
}

// UnDeploy 清理诱饵.
func (m *Manager) UnDeploy(path string) error {
	m.mu.Lock()
	delete(m.files, path)
	m.mu.Unlock()
	return os.Remove(path)
}

// Start hash 周期校验循环.
func (m *Manager) Start(ctx context.Context) {
	m.logger.Info("canary manager started", zap.Duration("interval", m.interval))
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.checkAll()
		}
	}
}

// checkAll 校验所有诱饵 hash.
func (m *Manager) checkAll() {
	m.mu.RLock()
	files := make([]*File, 0, len(m.files))
	for _, f := range m.files {
		files = append(files, f)
	}
	m.mu.RUnlock()

	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			// 文件被删 / 改名 = 触发 critical
			m.emit(Event{
				Path:      f.Path,
				Operation: "delete",
				Severity:  "critical",
				Time:      time.Now(),
			})
			continue
		}
		now := sha256Hex(data)
		if now != f.Hash {
			m.emit(Event{
				Path:      f.Path,
				Operation: "hash_changed",
				Severity:  "critical",
				HashOld:   f.Hash,
				HashNew:   now,
				Time:      time.Now(),
			})
			// 不更 cache hash, 持续告警直到 SOC 处理
		}
	}
}

func (m *Manager) emit(ev Event) {
	select {
	case m.events <- ev:
	default:
		m.logger.Warn("canary event queue full, drop")
	}
}

// NotifyFanotifyEvent fanotify watcher 触发 read/write/rename 时调.
//
// 仅当 hostExecAllowed=false (非白名单进程) 时升级为 critical.
func (m *Manager) NotifyFanotifyEvent(path, operation, comm string, pid int32, hostExecAllowed bool) {
	m.mu.RLock()
	_, isCanary := m.files[path]
	m.mu.RUnlock()
	if !isCanary {
		return
	}
	sev := "critical"
	if hostExecAllowed {
		sev = "high" // 白名单进程也访问 canary 可能是误操作
	}
	m.emit(Event{
		Path:      path,
		Operation: operation,
		PID:       pid,
		Comm:      comm,
		Severity:  sev,
		Time:      time.Now(),
	})
}

func sha256Hex(data []byte) string {
	h := sha256.New()
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// ReadHashFromDisk 给运维工具用 (校验单个诱饵当前 hash).
func ReadHashFromDisk(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
