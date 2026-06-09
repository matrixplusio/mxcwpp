// Package kms 实现 Manager 内嵌的 envelope encryption KMS。
//
// 设计目标:
//
//  1. 敏感字段 (KubeConfig / API Secret / SSH 凭证 / Webhook Token) 加密存库
//  2. 主密钥 (KEK) 从环境变量或文件加载, 永不入库
//  3. 数据密钥 (DEK) 每次加密随机生成, 用 KEK AES-GCM 包装后与密文一起存
//  4. 支持密钥轮换 (KEK 版本化, 解密时按密文 header 查找历史版本)
//
// 加密格式 (v1):
//
//	[0]      固定 0x01 (版本号)
//	[1..2]   KEK 版本号 (BE uint16)
//	[3..14]  随机 nonce (12 字节)
//	[15..30] 包装的 DEK (32 字节明文 → AES-GCM(KEK) → 48 字节)
//	[31..58] 真实 nonce for DEK (12 字节)
//	[59..]   AES-GCM(DEK) 密文 + 16 字节 tag
//
// 部署:
//
//	环境变量 MXSEC_KMS_KEK_V1 (base64 32 字节) 必填
//	可选 MXSEC_KMS_KEK_V2 ... 用于轮换 (新加密用最高版本)
package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	formatVersion  = 0x01
	dekSize        = 32           // AES-256 DEK
	nonceSize      = 12           // GCM standard
	wrappedDEKSize = dekSize + 16 // ciphertext + GCM tag
)

// KMS 是内嵌密钥管理服务。
type KMS struct {
	mu         sync.RWMutex
	keks       map[uint16][]byte // version → 32-byte KEK
	currentVer uint16            // 最新版本 (新加密用)
}

// New 从环境变量 MXSEC_KMS_KEK_V<N> 加载所有 KEK 版本。
//
// 至少需要一个 V1。多版本场景: V2 V3 ... 同时存在, currentVer = max。
func New() (*KMS, error) {
	k := &KMS{keks: make(map[uint16][]byte)}
	if err := k.LoadFromEnv(); err != nil {
		return nil, err
	}
	if len(k.keks) == 0 {
		return nil, errors.New("kms: MXSEC_KMS_KEK_V1 not set, refusing to start (敏感字段会以明文落库)")
	}
	return k, nil
}

// LoadFromEnv 扫描 MXSEC_KMS_KEK_V* 环境变量。
func (k *KMS) LoadFromEnv() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	versions := make([]uint16, 0, 4)
	for _, kv := range os.Environ() {
		idx := strings.Index(kv, "=")
		if idx < 0 {
			continue
		}
		key := kv[:idx]
		val := kv[idx+1:]
		if !strings.HasPrefix(key, "MXSEC_KMS_KEK_V") {
			continue
		}
		verStr := key[len("MXSEC_KMS_KEK_V"):]
		ver, err := strconv.ParseUint(verStr, 10, 16)
		if err != nil || ver == 0 || ver > 65535 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return fmt.Errorf("kms: MXSEC_KMS_KEK_V%d base64 decode: %w", ver, err)
		}
		if len(raw) != dekSize {
			return fmt.Errorf("kms: MXSEC_KMS_KEK_V%d must be %d bytes (got %d)", ver, dekSize, len(raw))
		}
		k.keks[uint16(ver)] = raw
		versions = append(versions, uint16(ver))
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	if len(versions) > 0 {
		k.currentVer = versions[len(versions)-1]
	}
	return nil
}

// Encrypt 用当前最高版本 KEK 加密 plaintext。
func (k *KMS) Encrypt(plaintext []byte) ([]byte, error) {
	k.mu.RLock()
	kek, ok := k.keks[k.currentVer]
	ver := k.currentVer
	k.mu.RUnlock()
	if !ok {
		return nil, errors.New("kms: no current KEK loaded")
	}
	// 生成 DEK
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("kms: gen DEK: %w", err)
	}
	// 用 KEK 包装 DEK (AES-GCM)
	wrapNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, wrapNonce); err != nil {
		return nil, fmt.Errorf("kms: gen wrap nonce: %w", err)
	}
	kekCipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	kekGCM, err := cipher.NewGCM(kekCipher)
	if err != nil {
		return nil, err
	}
	wrappedDEK := kekGCM.Seal(nil, wrapNonce, dek, nil)
	// 用 DEK 加密真实数据
	dataNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return nil, fmt.Errorf("kms: gen data nonce: %w", err)
	}
	dekCipher, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	dekGCM, err := cipher.NewGCM(dekCipher)
	if err != nil {
		return nil, err
	}
	dataCT := dekGCM.Seal(nil, dataNonce, plaintext, nil)
	// 组装 header
	//   1 byte version | 2 bytes KEK ver | 12 wrap nonce | 48 wrapped DEK | 12 data nonce | data CT
	out := make([]byte, 0, 1+2+nonceSize+wrappedDEKSize+nonceSize+len(dataCT))
	out = append(out, formatVersion)
	verBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(verBuf, ver)
	out = append(out, verBuf...)
	out = append(out, wrapNonce...)
	out = append(out, wrappedDEK...)
	out = append(out, dataNonce...)
	out = append(out, dataCT...)
	return out, nil
}

// Decrypt 反操作。按密文 header 中的 KEK 版本号查找对应 KEK。
func (k *KMS) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < 1+2+nonceSize+wrappedDEKSize+nonceSize {
		return nil, errors.New("kms: ciphertext too short")
	}
	if blob[0] != formatVersion {
		return nil, fmt.Errorf("kms: unsupported format version %d", blob[0])
	}
	ver := binary.BigEndian.Uint16(blob[1:3])
	k.mu.RLock()
	kek, ok := k.keks[ver]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("kms: KEK version %d not loaded (was it rotated out?)", ver)
	}
	off := 3
	wrapNonce := blob[off : off+nonceSize]
	off += nonceSize
	wrappedDEK := blob[off : off+wrappedDEKSize]
	off += wrappedDEKSize
	dataNonce := blob[off : off+nonceSize]
	off += nonceSize
	dataCT := blob[off:]
	// 解 DEK
	kekCipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	kekGCM, err := cipher.NewGCM(kekCipher)
	if err != nil {
		return nil, err
	}
	dek, err := kekGCM.Open(nil, wrapNonce, wrappedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("kms: unwrap DEK: %w", err)
	}
	// 解数据
	dekCipher, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	dekGCM, err := cipher.NewGCM(dekCipher)
	if err != nil {
		return nil, err
	}
	plaintext, err := dekGCM.Open(nil, dataNonce, dataCT, nil)
	if err != nil {
		return nil, fmt.Errorf("kms: decrypt data: %w", err)
	}
	return plaintext, nil
}

// EncryptString 便捷封装, 输出 base64 字符串供 GORM text 存储。
func (k *KMS) EncryptString(s string) (string, error) {
	blob, err := k.Encrypt([]byte(s))
	if err != nil {
		return "", err
	}
	return "kms:v1:" + base64.StdEncoding.EncodeToString(blob), nil
}

// DecryptString 解 base64 字符串。
//
// 兼容: 未加密的字段 (无 "kms:v1:" 前缀) 原样返回, 支持迁移期。
func (k *KMS) DecryptString(s string) (string, error) {
	if !strings.HasPrefix(s, "kms:v1:") {
		return s, nil
	}
	blob, err := base64.StdEncoding.DecodeString(s[len("kms:v1:"):])
	if err != nil {
		return "", fmt.Errorf("kms: base64 decode: %w", err)
	}
	plain, err := k.Decrypt(blob)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// CurrentVersion 当前活跃 KEK 版本 (新加密用).
func (k *KMS) CurrentVersion() uint16 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.currentVer
}

// GenerateKEK 生成 32 字节随机 KEK base64 编码, 用于初次部署写环境变量。
//
// 用法 (一次性):
//
//	go run ./cmd/tools/kms-gen-kek
//	→ 复制 base64 → systemd 环境文件 MXSEC_KMS_KEK_V1=...
func GenerateKEK() (string, error) {
	buf := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
