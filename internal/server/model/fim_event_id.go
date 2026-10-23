package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// DeriveFIMEventID 由事件各维度推导全局唯一的 FIM 事件主键。
//
// 为什么必须由服务端推导：
//
// FIM 插件的 event_id 是 `evt-%06d`，计数器是每轮基线比对的局部变量，每次扫描都从 1
// 重新开始。而 fim_events 以 event_id 为**全局主键**。两者叠加的后果不是"偶尔撞车"：
//   - Kafka 路径（DataType 6001）写入时 OnConflict DoNothing，于是全舰队每个序号只有
//     第一条能落库，之后任何主机、任何扫描的同序号事件都被静默丢弃，且不报任何错误；
//   - AC 直处理路径（6004）用裸 Create，冲突时报错，事件同样丢失。
//
// 文件被篡改而平台什么都没记下，是这条链路最不能接受的失败。
//
// 修在插件端要等全网 agent 升级才能止血；修在服务端对现有存量 agent 立即生效，
// 因此派生放在 model —— 两条写入路径共用同一份规则，不会各写一套而再次分叉。
// 原始 event_id 仍参与推导以保留可追溯性，但不再承担唯一性。
//
// 幂等性：推导只用事件自身字段，同一条消息重放必得同一主键，Kafka 路径的
// OnConflict DoNothing 去重语义因此依然成立——它原本就是为重放去重而设，
// 只是此前选错了键。
func DeriveFIMEventID(hostID, taskID, filePath, changeType, rawEventID string, detectedAtUnix int64) string {
	h := sha256.New()
	// 用 \x00 分隔，避免相邻字段拼接产生歧义（host "a"+task "bc" 与 "ab"+"c" 同串）。
	for _, part := range []string{
		hostID,
		taskID,
		filePath,
		changeType,
		strings.TrimSpace(rawEventID),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(detectedAtUnix))
	h.Write(ts[:])

	// 40 位十六进制（160 bit）足够避免碰撞，带前缀后仍远低于 varchar(64) 上限。
	return "fim-" + hex.EncodeToString(h.Sum(nil))[:40]
}
