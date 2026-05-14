// Package id 提供 Agent ID 管理功能
package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// InitID 初始化或获取 Agent ID
// 如果 ID 文件存在，则读取；否则生成新的 ID 并保存
func InitID(idFile string) (string, error) {
	// 确保目录存在
	dir := filepath.Dir(idFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create id directory: %w", err)
	}

	// 尝试读取现有 ID
	if data, err := os.ReadFile(idFile); err == nil {
		id := string(data)
		if len(id) > 0 {
			return id, nil
		}
	}

	// 生成新的 ID（32 字节，64 个十六进制字符）
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("failed to generate random id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	// 保存 ID 到文件
	if err := os.WriteFile(idFile, []byte(id), 0600); err != nil {
		return "", fmt.Errorf("failed to write id file: %w", err)
	}

	return id, nil
}
