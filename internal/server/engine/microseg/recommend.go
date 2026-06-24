package microseg

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Phase 2: 基于 Phase 1 观察数据生成 NetworkPolicy 推荐。
//
// 输出 dry-run 策略, 仍 observe 模式 (Phase 3 才 enforce)。
// 对标青藤零域 MSG 的 "建议策略" 视图。

// RecommendInput 是策略推荐的输入 (从历史聚合反查)。
type RecommendInput struct {
	TenantID   string
	Aggregates []*FlowAggregate
	// 仅保留连续 N 天观察到 ≥ minHits 的 (src, dst, port) 三元组
	MinDays  int
	MinHits  int64
	WindowAt time.Time // 推荐生成时刻 (用于策略 meta)
}

// PolicyRule 推荐策略单条规则。
type PolicyRule struct {
	Action   string // allow / deny
	SrcNS    string
	SrcPod   string
	DstNS    string
	DstPod   string
	DstPort  int32
	Protocol string
	// 观察侧统计 (帮助运维理解推荐依据)
	ObservedHits  int64
	ObservedBytes int64
	FirstSeen     time.Time
	LastSeen      time.Time
	Rationale     string
}

// PolicyRecommendation 是按 namespace 维度聚合的推荐集合。
type PolicyRecommendation struct {
	TenantID     string
	GeneratedAt  time.Time
	Namespace    string // 推荐落到哪个 ns
	AllowIngress []PolicyRule
	AllowEgress  []PolicyRule
	DefaultDeny  bool
	Summary      string
}

// Recommend 根据观察聚合生成策略推荐。
//
// 规则:
//
//  1. 同 (src→dst:port/proto) 在多个窗口被观察到 → 推荐 allow
//  2. 单 namespace 仅出现 N 条 allow → 同时推荐 default deny ingress
//  3. 出向只对外 (dst 不在集群) → 推荐 egress allow
//
// 不直接产 K8s NetworkPolicy yaml; 由后续 Sprint 的 renderer 输出。
func Recommend(in RecommendInput) []PolicyRecommendation {
	if in.MinHits <= 0 {
		in.MinHits = 5
	}
	if in.WindowAt.IsZero() {
		in.WindowAt = time.Now()
	}
	// 按 destination ns 分桶 (policy 落入目的 ns)
	byNS := map[string][]PolicyRule{}
	for _, a := range in.Aggregates {
		if a.HitCount < in.MinHits {
			continue
		}
		// 跳过空目的 (主机层 host → 外部, 不属容器微隔离范畴)
		if a.Key.DstNamespace == "" && a.Key.DstPodName == "" {
			continue
		}
		rule := PolicyRule{
			Action:        "allow",
			SrcNS:         a.Key.SrcNamespace,
			SrcPod:        a.Key.SrcPodName,
			DstNS:         a.Key.DstNamespace,
			DstPod:        a.Key.DstPodName,
			DstPort:       a.Key.DstPort,
			Protocol:      a.Key.Protocol,
			ObservedHits:  a.HitCount,
			ObservedBytes: a.TotalBytes,
			FirstSeen:     a.WindowStart,
			LastSeen:      a.WindowEnd,
			Rationale: fmt.Sprintf("观察到 %d 次会话,跨 %s,推荐 allow",
				a.HitCount, formatDuration(a.WindowEnd.Sub(a.WindowStart))),
		}
		ns := a.Key.DstNamespace
		byNS[ns] = append(byNS[ns], rule)
	}
	out := make([]PolicyRecommendation, 0, len(byNS))
	for ns, rules := range byNS {
		// 按 hits 排序, 高的优先 (top-N 截断后续 PR 加)
		sort.Slice(rules, func(i, j int) bool { return rules[i].ObservedHits > rules[j].ObservedHits })
		ingress, egress := splitDirection(rules, ns)
		out = append(out, PolicyRecommendation{
			TenantID:     in.TenantID,
			GeneratedAt:  in.WindowAt,
			Namespace:    ns,
			AllowIngress: ingress,
			AllowEgress:  egress,
			DefaultDeny:  len(ingress) > 0, // 有 allow 才能 default deny
			Summary: fmt.Sprintf("ns=%s allow_in=%d allow_out=%d default_deny=%v",
				ns, len(ingress), len(egress), len(ingress) > 0),
		})
	}
	// 排序保稳定 (test 友好)
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace < out[j].Namespace })
	return out
}

// splitDirection 按 src/dst ns 把规则划分到 ingress / egress 两侧。
//
// ns 视角:
//   - SrcNS != ns, DstNS == ns → ingress
//   - SrcNS == ns, DstNS != ns → egress
//   - SrcNS == ns, DstNS == ns → 同 ns 内, 默认归 ingress (东西向)
func splitDirection(rules []PolicyRule, ns string) (ingress, egress []PolicyRule) {
	for _, r := range rules {
		switch {
		case r.SrcNS != ns && r.DstNS == ns:
			ingress = append(ingress, r)
		case r.SrcNS == ns && r.DstNS != ns:
			egress = append(egress, r)
		case r.SrcNS == ns && r.DstNS == ns:
			ingress = append(ingress, r)
		}
	}
	return
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Truncate(time.Second).String()
	}
	if d < time.Hour {
		return d.Truncate(time.Minute).String()
	}
	return d.Truncate(time.Hour).String()
}

// RenderYAML 把单条 PolicyRecommendation 转 K8s NetworkPolicy YAML (dry-run 用)。
//
// 仅生成 yaml 文本供 UI 展示, 不下发到 K8s (Phase 3 才 enforce)。
func (p *PolicyRecommendation) RenderYAML() string {
	var b strings.Builder
	fmt.Fprintln(&b, "apiVersion: networking.k8s.io/v1")
	fmt.Fprintln(&b, "kind: NetworkPolicy")
	fmt.Fprintln(&b, "metadata:")
	fmt.Fprintf(&b, "  name: mxcwpp-recommend-%s\n", p.Namespace)
	fmt.Fprintf(&b, "  namespace: %s\n", p.Namespace)
	fmt.Fprintln(&b, "  annotations:")
	fmt.Fprintf(&b, "    mxcwpp.io/generated-at: %q\n", p.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "    mxcwpp.io/tenant-id: %q\n", p.TenantID)
	fmt.Fprintln(&b, "    mxcwpp.io/mode: observe")
	fmt.Fprintln(&b, "spec:")
	fmt.Fprintln(&b, "  podSelector: {}")
	if p.DefaultDeny {
		fmt.Fprintln(&b, "  policyTypes: [Ingress, Egress]")
	} else {
		fmt.Fprintln(&b, "  policyTypes: [Ingress]")
	}
	if len(p.AllowIngress) > 0 {
		fmt.Fprintln(&b, "  ingress:")
		for _, r := range p.AllowIngress {
			renderIngressRule(&b, r)
		}
	}
	if len(p.AllowEgress) > 0 {
		fmt.Fprintln(&b, "  egress:")
		for _, r := range p.AllowEgress {
			renderEgressRule(&b, r)
		}
	}
	return b.String()
}

func renderIngressRule(b *strings.Builder, r PolicyRule) {
	fmt.Fprintln(b, "    - from:")
	fmt.Fprintln(b, "        - namespaceSelector:")
	fmt.Fprintln(b, "            matchLabels:")
	fmt.Fprintf(b, "              kubernetes.io/metadata.name: %s\n", r.SrcNS)
	if r.SrcPod != "" {
		fmt.Fprintln(b, "          podSelector:")
		fmt.Fprintln(b, "            matchLabels:")
		fmt.Fprintf(b, "              app: %s\n", podToApp(r.SrcPod))
	}
	fmt.Fprintln(b, "      ports:")
	fmt.Fprintf(b, "        - protocol: %s\n", strings.ToUpper(r.Protocol))
	fmt.Fprintf(b, "          port: %d\n", r.DstPort)
}

func renderEgressRule(b *strings.Builder, r PolicyRule) {
	fmt.Fprintln(b, "    - to:")
	fmt.Fprintln(b, "        - namespaceSelector:")
	fmt.Fprintln(b, "            matchLabels:")
	fmt.Fprintf(b, "              kubernetes.io/metadata.name: %s\n", r.DstNS)
	if r.DstPod != "" {
		fmt.Fprintln(b, "          podSelector:")
		fmt.Fprintln(b, "            matchLabels:")
		fmt.Fprintf(b, "              app: %s\n", podToApp(r.DstPod))
	}
	fmt.Fprintln(b, "      ports:")
	fmt.Fprintf(b, "        - protocol: %s\n", strings.ToUpper(r.Protocol))
	fmt.Fprintf(b, "          port: %d\n", r.DstPort)
}

// podToApp 提取 pod 名前缀作 app label (Deployment 命名典型 <app>-<rs>-<hash>)。
func podToApp(podName string) string {
	parts := strings.Split(podName, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return podName
}
