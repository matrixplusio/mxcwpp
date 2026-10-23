package biz

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// PublishVulnBulletin 把漏洞通报发布到统一通知出口，并记录通知状态。
//
// 升级调度器按 last_notified_at 判断是否该再次提醒，入队即视为已通知：
// 发送失败由统一出口重试并留下投递记录，不在这里重复判断。
// 每次提醒（首次与各次升级）的去重身份不同，不会被抑制窗口挡掉。
func PublishVulnBulletin(db *gorm.DB, logger *zap.Logger, b *model.VulnBulletin) {
	var lines []string
	for _, kv := range [][2]string{
		{"CVE", b.CveID}, {"组件", b.Component}, {"CVSS", fmt.Sprintf("%.1f", b.CvssScore)},
		{"影响资产", fmt.Sprintf("%d 台", b.AffectedAssets)}, {"影响版本", b.AffectedVersions}, {"修复版本", b.FixedVersion},
	} {
		if kv[1] != "" && kv[1] != "0.0" {
			lines = append(lines, fmt.Sprintf("**%s：** %s", kv[0], kv[1]))
		}
	}
	if d := strings.TrimSpace(b.Description); d != "" {
		lines = append(lines, "", d)
	}
	outcome := alertbus.Publish(alertbus.Event{
		Category: model.NotifyCategoryVulnBulletin, Source: "vuln_bulletin",
		Severity:    b.Severity,
		Title:       fmt.Sprintf("%s 漏洞通报 %s：%s", b.Priority, b.BulletinNo, b.CveID),
		Description: strings.Join(lines, "\n"),
		DedupKey:    fmt.Sprintf("bulletin|%s|%d", b.BulletinNo, b.NotifyCount),
		RefTable:    "vuln_bulletins",
		RefID:       fmt.Sprint(b.ID),
	})
	if outcome != alertbus.OutcomeQueued {
		logger.Error("漏洞通报入队失败", zap.String("bulletin_no", b.BulletinNo), zap.String("outcome", string(outcome)))
		return
	}
	now := model.Now()
	db.Model(b).Updates(map[string]interface{}{
		"status":           model.BulletinStatusNotified,
		"notified_at":      &now,
		"last_notified_at": &now,
		"notify_count":     b.NotifyCount + 1,
	})
}
