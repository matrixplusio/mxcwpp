package model

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// 告警分组。
//
// 检测告警按「检测对象」合并：同一规则在同一主机上的命中并进一条告警、累加次数。
// 这条告警一旦被人关闭（resolved / ignored），它就是一份定案的记录，不再改写：
// 之后的命中生成一条新的「复发」告警，指向上一条。
//
// 此前的做法是永远复用同一条：resolved 再命中就改回 active（覆盖掉当初的结论），
// ignored 再命中则永远静音（之后的一切命中都并进一条没人看的告警）。前者丢了处置历史，
// 后者让一次忽略变成这台主机上这条规则的永久盲区。

// IsOpen 告警仍在吸收命中。
func (s AlertStatus) IsOpen() bool {
	return s == AlertStatusActive || s == AlertStatusSuppressed
}

// suppressedGroupSuffix 被抑制的命中单独成组：同一检测对象可能同时有一条
// 人在处置的 active 告警，和一条记录被抑制命中的 suppressed 告警，二者不能互相吞并。
const suppressedGroupSuffix = "|suppressed"

// SuppressedGroupKey 返回被抑制命中所用的分组键。
func SuppressedGroupKey(groupKey string) string { return groupKey + suppressedGroupSuffix }

// AlertSlot 是一次命中该落到哪里。
type AlertSlot struct {
	// Open 不为空时，命中并入这条仍开着的告警。
	Open *Alert
	// ResultID / RecurrenceOf 在 Open 为空时使用：新建告警的身份，以及它是谁的复发。
	ResultID     string
	RecurrenceOf *uint
}

// FindAlertSlot 查出组内最新一条告警，决定命中并入它还是新建一条。
//
// 复发告警的 result_id 由上一条的 id 决定，因此并发的两个 worker 会算出同一个 ID，
// 唯一索引保证只有一个插入成功——调用方遇到重复键时按 ResultID 重查并入即可。
func FindAlertSlot(db *gorm.DB, groupKey string) (AlertSlot, error) {
	var latest Alert
	err := db.Where("group_key = ?", groupKey).Order("id DESC").First(&latest).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 兼容尚未回填 group_key 的存量行：它们的 result_id 就是分组键。
		err = db.Where("result_id = ?", groupKey).First(&latest).Error
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return AlertSlot{ResultID: fitResultID(groupKey, "")}, nil
	}
	if err != nil {
		return AlertSlot{}, fmt.Errorf("查询告警分组 %s 失败: %w", groupKey, err)
	}
	if latest.Status.IsOpen() {
		return AlertSlot{Open: &latest}, nil
	}
	prev := latest.ID
	return AlertSlot{ResultID: fitResultID(groupKey, fmt.Sprintf("#%d", prev)), RecurrenceOf: &prev}, nil
}

// maxResultIDLen 与 alerts.result_id 的列宽一致。
const maxResultIDLen = 128

// fitResultID 由分组键加后缀得到 result_id。超出列宽时用分组键的摘要代替，
// 仍然确定、仍然唯一（复发后缀里的 id 全局唯一）。
func fitResultID(groupKey, suffix string) string {
	if len(groupKey)+len(suffix) <= maxResultIDLen {
		return groupKey + suffix
	}
	sum := sha1.Sum([]byte(groupKey))
	return "g" + hex.EncodeToString(sum[:]) + suffix
}

// UpsertGroupedAlert 把一次命中落到分组里：并入组内仍开着的告警，或新建一条（首次 / 复发）。
//
// build 只需填写告警内容；ResultID / GroupKey / RecurrenceOf 由这里设置。
// refresh 负责并入已有告警（各来源要更新的字段不同）。
// 返回值 created 非空表示新建了告警，调用方据此决定是否发首次通知。
func UpsertGroupedAlert(db *gorm.DB, groupKey string, build func() Alert, refresh func(existing *Alert) error) (created *Alert, err error) {
	// 最多两轮：第一轮插入撞上并发、而抢先插入的那条又恰好已被关闭时，重新判定一次。
	for attempt := 0; attempt < 2; attempt++ {
		slot, err := FindAlertSlot(db, groupKey)
		if err != nil {
			return nil, err
		}
		if slot.Open != nil {
			return nil, refresh(slot.Open)
		}
		alert := build()
		alert.ResultID = slot.ResultID
		alert.GroupKey = groupKey
		alert.RecurrenceOf = slot.RecurrenceOf
		err = db.Create(&alert).Error
		if err == nil {
			return &alert, nil
		}
		// 并发：另一个 worker 抢先插入了同一个 result_id（首次或同一次复发），并入它。
		var raced Alert
		if e := db.Where("result_id = ?", alert.ResultID).First(&raced).Error; e != nil {
			return nil, fmt.Errorf("写入告警失败: %w", err)
		}
		if raced.Status.IsOpen() {
			return nil, refresh(&raced)
		}
		// 抢先插入的那条已被关闭：关闭过的告警不能改写，重新判定落点。
	}
	return nil, fmt.Errorf("告警分组 %s 并发冲突，两轮均未落定", groupKey)
}
