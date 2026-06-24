//go:build linux

// Package quarantine 实现 Agent 端 文件隔离箱 (M1-8)。
//
// 流程:
//
//  1. 命中威胁 → Quarantine(path):
//     - 算 sha256
//     - mv 到 /var/mxcwpp/quarantine/<sha256>.qrn
//     - chmod 000 + 移除 ownership (chown root:root)
//     - 写 .meta JSON (原路径 / 原属主 / 原权限 / 隔离时间 / 触发规则)
//
//  2. 还原 Restore(qid):
//     - 读 .meta 回原路径
//     - chmod 复原 + chown 复原
//     - 写审计日志
//
//  3. 永久删除 Delete(qid):
//     - 物理 unlink + 删 .meta
//     - 写审计日志
//
// 与 plugins/scanner/engine/quarantine.go 区别:
//
//	那个是插件内的实现; 本文件是 Agent 主进程对齐的隔离箱基础设施,
//	allow av-scanner / fim / 任意检测模块共享。
package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	defaultDir = "/var/lib/mxcwpp/quarantine"
	metaSuffix = ".meta"
	quarSuffix = ".qrn"
)

// Manager 隔离箱管理器 (Agent 主进程级别, 多模块共享).
type Manager struct {
	dir    string
	logger *zap.Logger

	mu sync.Mutex
}

// NewManager 构造。dir 空时用默认 /var/lib/mxcwpp/quarantine。
func NewManager(dir string, logger *zap.Logger) (*Manager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if dir == "" {
		dir = defaultDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir quarantine dir: %w", err)
	}
	return &Manager{dir: dir, logger: logger}, nil
}

// Metadata 单条隔离记录元信息 (持久化为 <qid>.meta JSON)。
type Metadata struct {
	QID           string    `json:"qid"` // sha256 = 隔离箱内文件名
	OriginalPath  string    `json:"original_path"`
	OriginalUID   int       `json:"original_uid"`
	OriginalGID   int       `json:"original_gid"`
	OriginalMode  uint32    `json:"original_mode"`
	OriginalSize  int64     `json:"original_size"`
	OriginalMTime time.Time `json:"original_mtime"`
	SHA256        string    `json:"sha256"`
	TriggerRule   string    `json:"trigger_rule"`   // 触发规则 ID (e.g. EICAR / CVE-2024-3094)
	TriggerSource string    `json:"trigger_source"` // av-scanner / fim / honeypot / manual
	QuarantinedAt time.Time `json:"quarantined_at"`
}

// Quarantine 把文件移入隔离箱。
//
// 失败时尽量回滚 (mv 失败不影响原文件)。
func (m *Manager) Quarantine(path, triggerRule, triggerSource string) (*Metadata, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}

	hash, err := hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}

	dstPath := filepath.Join(m.dir, hash+quarSuffix)
	metaPath := filepath.Join(m.dir, hash+metaSuffix)

	// 已存在同 sha256? 视为重复, 仅更新 meta (累计 trigger 历史可后续 PR 加)
	if _, err := os.Stat(dstPath); err == nil {
		m.logger.Info("文件已在隔离箱, 跳过 (sha256 重复)",
			zap.String("qid", hash))
	} else {
		if err := safeMove(path, dstPath); err != nil {
			return nil, fmt.Errorf("move: %w", err)
		}
		// chmod 000 + chown root:root (即便 root 也得 chmod 000 防 cat)
		_ = os.Chmod(dstPath, 0o000)
		_ = os.Chown(dstPath, 0, 0)
	}

	meta := &Metadata{
		QID:           hash,
		OriginalPath:  path,
		OriginalSize:  info.Size(),
		OriginalMTime: info.ModTime(),
		OriginalMode:  uint32(info.Mode().Perm()),
		SHA256:        hash,
		TriggerRule:   triggerRule,
		TriggerSource: triggerSource,
		QuarantinedAt: time.Now(),
	}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		meta.OriginalUID = int(sys.Uid)
		meta.OriginalGID = int(sys.Gid)
	}

	if err := writeMeta(metaPath, meta); err != nil {
		return nil, fmt.Errorf("write meta: %w", err)
	}

	m.logger.Info("文件已隔离",
		zap.String("original", path),
		zap.String("qid", hash),
		zap.String("trigger", triggerRule),
		zap.String("source", triggerSource))
	return meta, nil
}

// Restore 还原 qid 对应文件到原路径。
//
// 原路径已存在 → 报错 (不覆盖, 防误冲)。
func (m *Manager) Restore(qid string) (*Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	metaPath := filepath.Join(m.dir, qid+metaSuffix)
	meta, err := readMeta(metaPath)
	if err != nil {
		return nil, err
	}

	dstPath := filepath.Join(m.dir, qid+quarSuffix)
	if _, err := os.Stat(meta.OriginalPath); err == nil {
		return meta, fmt.Errorf("original path already exists: %s", meta.OriginalPath)
	}

	if err := os.MkdirAll(filepath.Dir(meta.OriginalPath), 0o755); err != nil {
		return meta, fmt.Errorf("mkdir parent: %w", err)
	}
	if err := safeMove(dstPath, meta.OriginalPath); err != nil {
		return meta, fmt.Errorf("move back: %w", err)
	}
	_ = os.Chmod(meta.OriginalPath, os.FileMode(meta.OriginalMode))
	_ = os.Chown(meta.OriginalPath, meta.OriginalUID, meta.OriginalGID)
	_ = os.Remove(metaPath)

	m.logger.Info("文件已还原",
		zap.String("original", meta.OriginalPath),
		zap.String("qid", qid))
	return meta, nil
}

// Delete 永久删除 qid 对应文件 + meta。
func (m *Manager) Delete(qid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dstPath := filepath.Join(m.dir, qid+quarSuffix)
	metaPath := filepath.Join(m.dir, qid+metaSuffix)
	errs := []error{}
	if err := os.Remove(dstPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	m.logger.Info("隔离文件已永久删除", zap.String("qid", qid))
	return nil
}

// List 列所有 qid + 元信息。
func (m *Manager) List() ([]*Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	var out []*Metadata
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if !endsWith(name, metaSuffix) {
			continue
		}
		meta, err := readMeta(filepath.Join(m.dir, name))
		if err != nil {
			m.logger.Warn("读 meta 失败", zap.String("file", name), zap.Error(err))
			continue
		}
		out = append(out, meta)
	}
	return out, nil
}

// safeMove 优先 rename, 跨设备 fallback 到 copy+remove。
func safeMove(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// fallback: copy + remove
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return os.Remove(src)
}

func hashFile(path string) (string, error) {
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

func writeMeta(path string, m *Metadata) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func readMeta(path string) (*Metadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
