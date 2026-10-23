package notify

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/matrixplusio/mxcwpp/internal/common/ssrf"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// EventMessage 统一出口的一条通知内容，与告警来源无关。
// 分发器（alertbus.Dispatcher）匹配渠道后，对每个渠道调用 DeliverEvent。
type EventMessage struct {
	Category     model.NotifyCategory
	Kind         string // firing / resolved / digest
	Source       string
	Severity     string
	Title        string
	Description  string
	HostID       string
	Hostname     string
	IP           string
	BusinessLine string
	OccurredAt   time.Time
	RefTable     string
	RefID        string
}

var categoryLabel = map[model.NotifyCategory]string{
	model.NotifyCategoryDetection:     "规则检测",
	model.NotifyCategoryInfraAlert:    "平台基础设施",
	model.NotifyCategoryBehaviorAlert: "行为基线偏离",
	model.NotifyCategoryAnomalyAlert:  "ML 异常",
	model.NotifyCategoryIncident:      "关联事件",
	model.NotifyCategoryKubeAlert:     "容器安全",
	model.NotifyCategoryBaselineAlert: "基线安全",
	model.NotifyCategoryAgentOffline:  "Agent 状态",
	model.NotifyCategoryFIMAlert:      "文件完整性",
	model.NotifyCategoryVirusAlert:    "病毒查杀",
	model.NotifyCategoryVulnBulletin:  "漏洞通报",
	model.NotifyCategoryADAuditAlert:  "AD 审计",
}

var severityLabel = map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}

// EnrichHost 补全主机名、IP、业务线：发布方常只知道 host_id，卡片上要给人看的是名字和业务线。
func (s *NotificationService) EnrichHost(m *EventMessage) {
	if m.HostID == "" {
		return
	}
	var host model.Host
	if err := s.db.Select("hostname, ipv4, business_line").First(&host, "host_id = ?", m.HostID).Error; err != nil {
		return
	}
	if m.Hostname == "" {
		m.Hostname = host.Hostname
	}
	if m.IP == "" && len(host.IPv4) > 0 {
		m.IP = host.IPv4[0]
	}
	if m.BusinessLine == "" {
		m.BusinessLine = host.BusinessLine
	}
}

// MatchChannels 返回应收到这条消息的通知配置：启用、类别相同、等级命中、主机范围命中。
// 渠道没配等级视为不接收——旧路径里有的当「全部」有的当「不发」，统一出口按保守的一侧。
// 主机范围是业务线时，没有主机的告警（如基础设施）只会命中「全局」范围的渠道。
func (s *NotificationService) MatchChannels(m *EventMessage) ([]model.Notification, error) {
	all, err := s.ChannelsFor(m.Category)
	if err != nil {
		return nil, err
	}
	return s.filterNotifications(all, &AlertData{HostID: m.HostID, Severity: m.Severity}), nil
}

// ChannelsFor 某类别下启用且配了等级的通知配置。
func (s *NotificationService) ChannelsFor(category model.NotifyCategory) ([]model.Notification, error) {
	var all []model.Notification
	if err := s.db.Where("enabled = ? AND notify_category = ?", true, category).Find(&all).Error; err != nil {
		return nil, err
	}
	out := all[:0]
	for _, n := range all {
		if len(n.Severities) > 0 {
			out = append(out, n)
		}
	}
	return out, nil
}

// ChannelAccepts 该渠道是否接收这台主机、这个等级的告警（等级与主机范围）。
func (s *NotificationService) ChannelAccepts(n *model.Notification, hostID, severity string) bool {
	return s.matchSeverity(n.Severities, severity) && s.matchScope(n, &AlertData{HostID: hostID})
}

// AlertSourceCategory 告警表来源对应的通知类别，供统一出口的告警表桥接与日报使用。
func AlertSourceCategory(source string) model.NotifyCategory { return alertSourceCategory(source) }

// DeliverEvent 把消息发到一个渠道。用带 SSRF 防护、有超时的客户端——旧路径里只有「测试发送」这么做。
func (s *NotificationService) DeliverEvent(n *model.Notification, m *EventMessage) error {
	var message map[string]interface{}
	if n.Type == model.NotificationTypeLark {
		message = s.buildLarkEventCard(n, m)
	} else {
		message = s.buildWebhookEvent(n, m)
	}
	return s.postWith(s.eventClient(), n.Config.WebhookURL, message)
}

// eventClient 默认 SSRF 安全客户端；测试可经 SetHTTPClient 注入。
func (s *NotificationService) eventClient() *http.Client {
	if s.httpClient != nil {
		return s.httpClient
	}
	return ssrf.NewSafeClient(10 * time.Second)
}

// SetHTTPClient 替换统一出口使用的 HTTP 客户端（测试用：本地假 webhook 在受限网段内）。
func (s *NotificationService) SetHTTPClient(c *http.Client) { s.httpClient = c }

// EventDetailURL 「查看详情」的地址。路径必须是前端真实存在的页面（TestNotificationLinksExist 钉住）。
func (s *NotificationService) EventDetailURL(n *model.Notification, m *EventMessage) string {
	base := s.resolveFrontendURL(n.FrontendURL)
	if base == "" {
		return ""
	}
	return refDetailURL(base, m.RefTable, m.RefID)
}

func refDetailURL(base, refTable, refID string) string {
	switch refTable {
	case "alerts":
		var id uint
		if _, err := fmt.Sscan(refID, &id); err == nil && id > 0 {
			return alertCenterURL(base, id)
		}
		return base + "/alert-center/alerts"
	case "incidents":
		return base + "/alert-center/incidents"
	case "anomaly_alerts":
		return base + "/detection/anomaly"
	case "behavior_alerts":
		return base + "/detection/bde"
	case "kube_baseline_alerts":
		return base + "/kube/baseline"
	case "kube_alarms":
		return base + "/kube/alarms"
	case "fim_events":
		return base + "/fim/events"
	case "antivirus_scan_results":
		return base + "/virus/scan"
	case "vuln_bulletins":
		return base + "/vuln-management/bulletins"
	default:
		return base + "/alert-center/alerts"
	}
}

func (s *NotificationService) buildLarkEventCard(n *model.Notification, m *EventMessage) map[string]interface{} {
	label := categoryLabel[m.Category]
	if label == "" {
		label = string(m.Category)
	}
	sev := severityLabel[m.Severity]
	if sev == "" {
		sev = m.Severity
	}
	lines := []string{fmt.Sprintf("**%s**", m.Title), fmt.Sprintf("**等级：** %s", sev)}
	if m.Hostname != "" || m.HostID != "" {
		host := m.Hostname
		if host == "" {
			host = m.HostID
		}
		if m.IP != "" {
			host += "（" + m.IP + "）"
		}
		lines = append(lines, "**主机：** "+host)
	}
	if m.BusinessLine != "" {
		lines = append(lines, "**业务线：** "+m.BusinessLine)
	}
	occurred := m.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	lines = append(lines, "**时间：** "+occurred.Format("2006-01-02 15:04:05"))

	elements := []map[string]interface{}{larkTextDiv(strings.Join(lines, "\n"))}
	if d := strings.TrimSpace(m.Description); d != "" {
		elements = append(elements, larkHR(), larkTextDiv(d))
	}
	if url := s.EventDetailURL(n, m); url != "" {
		elements = append(elements, larkHR(), larkActionButton("查看详情", url))
	}
	title, template := "【"+label+"】"+sev+"告警", s.getSeverityTemplate(m.Severity)
	switch m.Kind {
	case model.NotifyKindResolved:
		title, template = "【"+label+"】已恢复", "green"
	case model.NotifyKindDigest:
		title, template = "【"+label+"】未处理告警日报", "blue"
	}
	return s.buildLarkCardMessage(n, title, template, elements)
}

func (s *NotificationService) buildWebhookEvent(n *model.Notification, m *EventMessage) map[string]interface{} {
	occurred := m.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now()
	}
	return map[string]interface{}{
		"category":      m.Category,
		"kind":          m.Kind,
		"source":        m.Source,
		"severity":      m.Severity,
		"title":         m.Title,
		"description":   m.Description,
		"host_id":       m.HostID,
		"hostname":      m.Hostname,
		"ip":            m.IP,
		"business_line": m.BusinessLine,
		"occurred_at":   occurred.Format(time.RFC3339),
		"url":           s.EventDetailURL(n, m),
	}
}

// SampleEvent 测试发送用的示例告警：按渠道类别给出贴近真实的内容，走与真实告警相同的模板。
func SampleEvent(category model.NotifyCategory) *EventMessage {
	m := &EventMessage{
		Category: category, Kind: model.NotifyKindFiring, Source: "test", Severity: "high",
		HostID: "test-host-001", Hostname: "测试主机", IP: "192.0.2.10", BusinessLine: "测试业务线",
		OccurredAt: time.Now(), RefTable: "alerts",
	}
	switch category {
	case model.NotifyCategoryDetection:
		m.Title, m.Description = "【测试】可疑进程执行", "这是一条测试通知：检测到可疑的命令执行行为。"
	case model.NotifyCategoryInfraAlert:
		m.Title, m.Description = "【测试】DiskWillFillIn4Hours (node-exporter)", "这是一条测试通知：磁盘预计 4 小时内写满。"
		m.Hostname, m.HostID, m.IP, m.BusinessLine = "", "", "", "" // 基础设施告警没有主机，也就没有业务线
	case model.NotifyCategoryAgentOffline:
		m.Title, m.Description = "【测试】Agent 离线", "这是一条测试通知：主机的 Agent 已断开连接。"
	case model.NotifyCategoryFIMAlert:
		m.Title, m.Description, m.RefTable = "【测试】文件变更：/etc/passwd", "这是一条测试通知：关键文件被修改。", "fim_events"
	case model.NotifyCategoryVirusAlert:
		m.Title, m.Description, m.RefTable = "【测试】发现恶意文件", "这是一条测试通知：在 /tmp 下发现可疑可执行文件。", "antivirus_scan_results"
	case model.NotifyCategoryKubeAlert:
		m.Title, m.Description, m.RefTable = "【测试】创建特权容器", "这是一条测试通知：命名空间 default 中创建了特权容器。", "kube_alarms"
		m.Hostname, m.HostID, m.IP, m.BusinessLine = "", "", "", "" // K8s 告警没有主机，也就没有业务线
	case model.NotifyCategoryVulnBulletin:
		m.Title, m.Description, m.RefTable = "【测试】P1 漏洞通报", "这是一条测试通知：发现影响在线资产的高危漏洞。", "vuln_bulletins"
	default:
		m.Title, m.Description = "【测试】告警通知", "这是一条测试通知，用于验证通知配置是否正确。"
	}
	return m
}
