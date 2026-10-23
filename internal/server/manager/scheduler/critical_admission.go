package scheduler

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/alertbus"
	"github.com/matrixplusio/mxcwpp/internal/server/audit"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/biz/detquality"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// runCriticalAdmissionReview 检查 critical 准入清单，对已被研判结果证明不可信的规则提出移出建议。
//
// 没有这一步，准入清单只是把「规则作者写了 critical 就永远是 critical」换成
// 「初始清单里有就永远有」：规则后来变吵了，仍要等人想起来去改。
// 建议会走通知出口：一条没人看见的建议和没提一样。
func runCriticalAdmissionReview(svc *detquality.Service, logger *zap.Logger) error {
	suggestions, err := svc.SuggestCriticalDemotions(time.Now())
	if err != nil {
		logger.Warn("critical 准入复核失败", zap.Error(err))
	}
	// 出错前已经提出的照样通知并记审计。
	for _, sg := range suggestions {
		alertbus.Publish(alertbus.Event{
			Category: model.NotifyCategoryInfraAlert,
			Source:   "critical_admission",
			Severity: "medium",
			Title:    "建议把规则移出 critical 准入：" + sg.RuleName,
			Description: fmt.Sprintf("规则 %s（%s）%s。\n它目前仍在准入清单里，命中照常以 critical 告警。"+
				"请在「威胁检测 → 规则」里确认：移出，或保留并写明原因。", sg.RuleName, sg.RuleID, sg.Reason),
			DedupKey: "critical-admission-suggest|" + sg.RuleID,
		})
		audit.Record(context.Background(), audit.Event{
			ActorType:    model.ActorTypeSystem,
			Username:     "critical-admission",
			Action:       "rule.critical_admission_suggest",
			ResourceType: "detection_rule",
			ResourceID:   sg.RuleID,
			ChangeDetail: "建议移出准入（" + sg.Reason + "）",
		})
	}
	return err
}
