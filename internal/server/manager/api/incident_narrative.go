package api

import (
	"fmt"
	"sort"
	"strings"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// incidentCatMeta 告警分类 → 攻击阶段中文名 + kill-chain 顺序 + 处置建议。
// 用成员告警的 category 而非 incident.Tactics 编叙事(category 数据更完整可靠)。
type incidentCatMeta struct {
	name  string
	order int
	rec   string
}

var incidentCategoryMeta = map[string]incidentCatMeta{
	"reconnaissance":       {"侦察", 0, "核查来源 IP,收紧对外暴露面"},
	"initial_access":       {"初始访问", 1, "排查 Web/服务入口是否被利用,检查可疑上传与 Webshell"},
	"execution":            {"执行", 2, "核对可疑进程命令行与父进程是否合法"},
	"webshell":             {"Webshell", 2, "定位并清除 Webshell,审计 Web 目录写入"},
	"reverse_shell":        {"反弹Shell", 2, "立即隔离主机,阻断外联,排查反弹来源"},
	"persistence":          {"持久化", 3, "检查 cron/systemd/authorized_keys/ld.so.preload 是否被篡改并清除"},
	"privilege_escalation": {"权限提升", 4, "核查 sudo/setuid 与内核提权痕迹,修补相关漏洞"},
	"defense_evasion":      {"防御规避", 5, "核查 rootkit/日志篡改/无文件执行,做完整性校验"},
	"credential_access":    {"凭证访问", 6, "立即轮换受影响凭证(shadow/ssh key/云凭证),排查泄露范围"},
	"discovery":            {"发现", 7, "确认侦察行为是否来自合法运维"},
	"lateral_movement":     {"横向移动", 8, "排查内网连接,隔离受影响主机,核查横移凭证"},
	"network_scan":         {"网络扫描", 8, "封禁扫描源,核查暴露服务"},
	"collection":           {"数据收集", 9, "排查敏感数据访问与打包行为"},
	"command_and_control":  {"命令与控制", 10, "封禁可疑外联 IP/域名,隔离主机"},
	"c2_communication":     {"命令与控制", 10, "封禁可疑外联 IP/域名,隔离主机"},
	"exfiltration":         {"数据渗出", 11, "阻断外传通道,评估泄露数据范围"},
	"cryptomining":         {"挖矿", 12, "终止挖矿进程,清除持久化,排查入侵入口"},
	"ransomware":           {"勒索", 12, "立即隔离主机,停止加密进程,启动备份恢复流程"},
	"impact":               {"影响/破坏", 12, "隔离主机,评估业务影响,启动应急恢复"},
	"ioc_hit":              {"威胁情报命中", 10, "核查命中的 IOC 上下文,封禁相关指标"},
	"attack_chain":         {"已确认攻击链", 5, "高置信多步攻击,优先处置:隔离主机并溯源完整链路"},
}

func catMetaOf(category string) incidentCatMeta {
	if m, ok := incidentCategoryMeta[category]; ok {
		return m
	}
	return incidentCatMeta{name: category, order: 99, rec: ""}
}

// incidentStage 叙事中的一个攻击阶段
type incidentStage struct {
	Category   string   `json:"category"`
	Name       string   `json:"name"`
	AlertCount int      `json:"alert_count"`
	Examples   []string `json:"examples"` // 代表性告警标题(最多 3 条)
}

// buildIncidentNarrative 由成员告警生成攻击阶段、叙事文本与处置建议。
func buildIncidentNarrative(inc model.Incident, alerts []model.Alert) (stages []incidentStage, narrative string, recommendations []string) {
	// 按 category 聚合
	type agg struct {
		count    int
		examples []string
	}
	byCat := map[string]*agg{}
	for _, a := range alerts {
		cat := a.Category
		if cat == "" {
			cat = "other"
		}
		g, ok := byCat[cat]
		if !ok {
			g = &agg{}
			byCat[cat] = g
		}
		g.count++
		if len(g.examples) < 3 && a.Title != "" {
			g.examples = append(g.examples, a.Title)
		}
	}

	for cat, g := range byCat {
		m := catMetaOf(cat)
		stages = append(stages, incidentStage{Category: cat, Name: m.name, AlertCount: g.count, Examples: g.examples})
	}
	// 按 kill-chain 顺序排
	sort.SliceStable(stages, func(i, j int) bool {
		return catMetaOf(stages[i].Category).order < catMetaOf(stages[j].Category).order
	})

	// 叙事文本
	hostLabel := inc.Hostname
	if hostLabel == "" {
		hostLabel = inc.HostID
	}
	stageNames := make([]string, 0, len(stages))
	for _, s := range stages {
		stageNames = append(stageNames, s.Name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "主机 %s 上检测到 %d 个攻击阶段", hostLabel, len(stages))
	if len(stageNames) > 0 {
		fmt.Fprintf(&b, ":%s", strings.Join(stageNames, " → "))
	}
	fmt.Fprintf(&b, "。共 %d 条告警", inc.AlertCount)
	if inc.BehaviorAlertCount > 0 {
		fmt.Fprintf(&b, "、%d 项行为异常", inc.BehaviorAlertCount)
	}
	fmt.Fprintf(&b, ",综合风险 %.0f/100。", inc.RiskScore)
	for _, s := range stages {
		if s.Category == "attack_chain" {
			b.WriteString("已确认存在多步攻击链(高置信)。")
			break
		}
	}
	narrative = b.String()

	// 去重的处置建议(按阶段顺序)
	seen := map[string]struct{}{}
	for _, s := range stages {
		rec := catMetaOf(s.Category).rec
		if rec == "" {
			continue
		}
		if _, ok := seen[rec]; ok {
			continue
		}
		seen[rec] = struct{}{}
		recommendations = append(recommendations, rec)
	}
	return stages, narrative, recommendations
}

// sortAlertsByTime 按首次发现时间升序排成时间线
func sortAlertsByTime(alerts []model.Alert) {
	sort.SliceStable(alerts, func(i, j int) bool {
		return alerts[i].FirstSeenAt.Before(alerts[j].FirstSeenAt)
	})
}
