// Package fileutil 提供通用文件工具函数
package fileutil

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// SHA256Sum 计算文件的 SHA256 校验和，返回十六进制字符串
func SHA256Sum(filePath string) (string, error) {
	f, err := os.Open(filePath)
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
