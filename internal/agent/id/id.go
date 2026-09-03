// Package id 提供 Agent ID 管理功能
package id

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// stableIDSources 派生稳定 Agent ID 的机器指纹来源（按优先级）。
// machine-id 在重装系统包/重启后保持不变；product_uuid 为硬件级 UUID（VM/裸机稳定）。
var stableIDSources = []string{
	"/etc/machine-id",
	"/var/lib/dbus/machine-id",
	"/sys/class/dmi/id/product_uuid",
}

// InitID 初始化或获取 Agent ID。
//
// 优先级：① 已有 ID 文件 → 直接复用；② 从机器指纹(machine-id/product_uuid)派生；
// ③ 随机兜底。派生保证 agent 重装(删 ID 文件)后能重算出同一 ID，从而 host_id 稳定，
// 不丢服务端 per-host 状态(BDE 行为基线、资产关联等)。
func InitID(idFile string) (string, error) {
	// 确保目录存在
	dir := filepath.Dir(idFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create id directory: %w", err)
	}

	// ① 已有 ID 文件 → 复用（现有 agent 不变，零 churn）
	if data, err := os.ReadFile(idFile); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	}

	// ② 从机器指纹派生稳定 ID；③ 派生不到则随机兜底
	id := deriveStableID()
	if id == "" {
		idBytes := make([]byte, 32)
		if _, err := rand.Read(idBytes); err != nil {
			return "", fmt.Errorf("failed to generate random id: %w", err)
		}
		id = hex.EncodeToString(idBytes)
	}

	// 保存 ID 到文件
	if err := os.WriteFile(idFile, []byte(id), 0600); err != nil {
		return "", fmt.Errorf("failed to write id file: %w", err)
	}

	return id, nil
}

// deriveStableID 从机器指纹派生确定性 Agent ID（64 hex，与随机 ID 格式一致）。
// 加盐 hash 避免直接暴露原始 machine-id；任一来源可读且非空即采用。派生不到返回空串。
func deriveStableID() string {
	for _, p := range stableIDSources {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(data))
		if v == "" {
			continue
		}
		sum := sha256.Sum256([]byte("mxcwpp-agent:" + v))
		return hex.EncodeToString(sum[:])
	}
	return ""
}
