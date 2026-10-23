// Package id 提供 Agent ID 管理功能
package id

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// stableIDSources 派生 Agent ID 的机器指纹来源（按优先级，取第一个可读值）。
// 这是最早的派生规则，必须保持不变：普通机器重装后要算回同一个 ID，
// 服务端的 per-host 状态（行为基线、资产、业务线）才不会丢。
var stableIDSources = []string{
	"/etc/machine-id",
	"/var/lib/dbus/machine-id",
	"/sys/class/dmi/id/product_uuid",
}

// fingerprintSources 组成机器指纹的各项。克隆机器通常只共享其中一部分
// （模板克隆共享 machine-id，硬件 UUID 与磁盘 UUID 各不相同），合在一起才能区分。
// 不用 MAC：换网卡就会漂移，把同一台机器误判为克隆。
var fingerprintSources = map[string][]string{
	"machine_id":   {"/etc/machine-id", "/var/lib/dbus/machine-id"},
	"product_uuid": {"/sys/class/dmi/id/product_uuid"},
	"board_serial": {"/sys/class/dmi/id/board_serial"},
}

// rootfsUUID 返回根文件系统的 UUID，取不到返回空串（非 Linux / 容器内常见）。
var rootfsUUID = rootFSUUID

// Result 是一次 ID 解析的结果。
type Result struct {
	ID string
	// Fingerprint 本机当前指纹，随连接上报给服务端比对；取不到时为空串。
	Fingerprint string
	// Cloned 表示 ID 文件来自别的机器（指纹与当初记录的不一致），已丢弃并重新派生。
	Cloned bool
}

// fingerprintFile 记录写 ID 文件时的机器指纹，用来识别「ID 文件是随镜像复制来的」。
func fingerprintFile(idFile string) string { return idFile + ".fingerprint" }

// Resolve 确定本机的 Agent ID。
//
// ① 已有 ID 文件且指纹一致（或旧版本未记录指纹）→ 沿用，并补记指纹基线；
// ② 已有 ID 文件但指纹变了 → ID 文件是被克隆过来的，连同 staleFiles（客户端证书）一起丢弃，按③重新派生；
// ③ 无 ID 文件 → 按最早的规则派生（兼容既有 ID），派生不到再用组合指纹，最后随机。
//
// 本地无法判断两台机器是否共享了 machine-id，那由服务端在连接时比对指纹发现，见 Reset。
func Resolve(idFile string, staleFiles []string) (Result, error) {
	if err := os.MkdirAll(filepath.Dir(idFile), 0755); err != nil {
		return Result{}, fmt.Errorf("failed to create id directory: %w", err)
	}
	fp := Fingerprint()

	if data, err := os.ReadFile(idFile); err == nil {
		if existing := strings.TrimSpace(string(data)); existing != "" {
			stored, _ := os.ReadFile(fingerprintFile(idFile))
			recorded := strings.TrimSpace(string(stored))
			switch {
			case recorded == "" || fp == "":
				// 旧版本升级上来还没有基线，或本机取不到指纹：沿用，能记就补记。
				writeFingerprint(idFile, fp)
				return Result{ID: existing, Fingerprint: fp}, nil
			case recorded == fp:
				return Result{ID: existing, Fingerprint: fp}, nil
			}
			// 指纹变了：这份 ID 属于另一台机器。
			discard(idFile, staleFiles)
			id, err := assign(idFile, firstCandidate(fp), fp)
			return Result{ID: id, Fingerprint: fp, Cloned: true}, err
		}
	}

	id, err := assign(idFile, firstCandidate(fp), fp)
	return Result{ID: id, Fingerprint: fp}, err
}

// Reset 在服务端判定身份冲突后换一个 ID：按「最早规则 → 组合指纹 → 随机」的顺序取下一个，
// 同时丢弃 staleFiles（旧 ID 的客户端证书），让 agent 以新身份重新 enroll。
//
// 冲突组里第一台保住原 ID，其余每台各自前进一步：共享 machine-id 的克隆落到组合指纹，
// 连组合指纹都相同的完全克隆落到随机 ID。
func Reset(idFile string, staleFiles []string) (string, error) {
	data, _ := os.ReadFile(idFile)
	current := strings.TrimSpace(string(data))
	fp := Fingerprint()

	next := randomID()
	if legacy := deriveStableID(); current != "" && current == legacy {
		if composite := compositeID(fp); composite != "" && composite != current {
			next = composite
		}
	}
	discard(idFile, staleFiles)
	return assign(idFile, next, fp)
}

// firstCandidate 无 ID 文件时的首选 ID。
func firstCandidate(fp string) string {
	if id := deriveStableID(); id != "" {
		return id
	}
	if id := compositeID(fp); id != "" {
		return id
	}
	return randomID()
}

func assign(idFile, id, fp string) (string, error) {
	if err := os.WriteFile(idFile, []byte(id), 0600); err != nil {
		return "", fmt.Errorf("failed to write id file: %w", err)
	}
	writeFingerprint(idFile, fp)
	return id, nil
}

func writeFingerprint(idFile, fp string) {
	if fp != "" {
		_ = os.WriteFile(fingerprintFile(idFile), []byte(fp), 0600)
	}
}

func discard(idFile string, staleFiles []string) {
	_ = os.Remove(idFile)
	_ = os.Remove(fingerprintFile(idFile))
	for _, f := range staleFiles {
		_ = os.Remove(f)
	}
}

// Fingerprint 本机指纹：各来源取值排序拼接后的 SHA-256，一项都取不到时返回空串。
func Fingerprint() string {
	parts := map[string]string{}
	for name, paths := range fingerprintSources {
		for _, p := range paths {
			if v := readTrim(p); v != "" {
				parts[name] = v
				break
			}
		}
	}
	if v := rootfsUUID(); v != "" {
		parts["rootfs_uuid"] = v
	}
	if len(parts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(parts))
	for k := range parts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + parts[k] + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func compositeID(fp string) string {
	if fp == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("mxcwpp-agent:v2:" + fp))
	return hex.EncodeToString(sum[:])
}

// deriveStableID 按最早的规则派生 Agent ID（64 hex）。
// 加盐 hash 避免直接暴露原始 machine-id；任一来源可读且非空即采用。派生不到返回空串。
func deriveStableID() string {
	for _, p := range stableIDSources {
		if v := readTrim(p); v != "" {
			sum := sha256.Sum256([]byte("mxcwpp-agent:" + v))
			return hex.EncodeToString(sum[:])
		}
	}
	return ""
}

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败意味着系统熵源不可用，此时任何 ID 都不可信，直接终止。
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}

func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// InitID 是 Resolve 的简化入口，不处理证书文件。
func InitID(idFile string) (string, error) {
	r, err := Resolve(idFile, nil)
	return r.ID, err
}
