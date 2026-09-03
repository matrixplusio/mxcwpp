// Package microseg — NetworkPolicy 自动生成器 (C5).
//
// 设计:
//   - 输入: 24h 观察期内 Pod→Pod 流量 (来源 cilium hubble / kube-state / eBPF cgroup_skb)
//   - 输出: K8s NetworkPolicy YAML (default deny + 显式 allow 已观察到的流量)
//   - 策略: ingress + egress 双向声明
//
// 生成原则:
//   - 默认 deny: 所有 namespace 走 ingress: []
//   - 然后按 srcLabel → dstLabel 流量记录加 allow rule
//   - 同 namespace 用 podSelector + ports
//   - 跨 namespace 用 namespaceSelector + podSelector
//   - 出公网用 ipBlock: 0.0.0.0/0 except 私网 段
package microseg

import (
	"fmt"
	"sort"
	"strings"
)

// FlowEdge 一条观察到的流量.
type FlowEdge struct {
	SrcNamespace string
	SrcPodLabels map[string]string
	DstNamespace string
	DstPodLabels map[string]string
	Protocol     string // TCP / UDP
	Port         int
}

// PolicyGenConfig 生成器配置.
type PolicyGenConfig struct {
	DefaultDeny   bool   // 是否生成 default-deny 基础策略
	IncludeEgress bool   // 是否含 egress
	MinFlowCount  int    // 流量观察次数下限 (过滤偶发流量)
	NameTemplate  string // policy name 模板, 默认 "auto-{namespace}"
}

// ingressRule 单条 ingress (file scope).
type ingressRule struct {
	fromNs     string
	fromLabels map[string]string
	proto      string
	port       string
}

// GeneratePolicies 把流量集合聚合成 NetworkPolicy YAML.
//
// 返回 namespace → YAML 字符串映射 (一 ns 一 policy file).
func GeneratePolicies(edges []FlowEdge, cfg PolicyGenConfig) map[string]string {
	if cfg.NameTemplate == "" {
		cfg.NameTemplate = "auto-{namespace}"
	}
	if cfg.MinFlowCount <= 0 {
		cfg.MinFlowCount = 1
	}

	// 1. 按 (srcNs, srcLabels, dstNs, dstLabels, port, proto) 聚合次数
	type key struct {
		srcNs, dstNs, proto string
		srcL, dstL          string // 序列化后的 labels
		port                int
	}
	counts := map[key]int{}
	for _, e := range edges {
		k := key{
			srcNs: e.SrcNamespace, dstNs: e.DstNamespace,
			srcL: labelsKey(e.SrcPodLabels), dstL: labelsKey(e.DstPodLabels),
			proto: e.Protocol, port: e.Port,
		}
		counts[k]++
	}

	// 2. 按 dst ns 聚合 (NetworkPolicy 部署在 dst ns)
	byNs := map[string][]ingressRule{}
	for k, c := range counts {
		if c < cfg.MinFlowCount {
			continue
		}
		byNs[k.dstNs] = append(byNs[k.dstNs], ingressRule{
			fromNs:     k.srcNs,
			fromLabels: parseLabelsKey(k.srcL),
			proto:      k.proto,
			port:       fmt.Sprintf("%d", k.port),
		})
	}

	out := map[string]string{}
	for ns, rules := range byNs {
		out[ns] = renderPolicy(ns, rules, cfg)
	}
	return out
}

// renderPolicy 生成单 ns 的 NetworkPolicy YAML.
func renderPolicy(ns string, rules []ingressRule, cfg PolicyGenConfig) string {
	name := strings.ReplaceAll(cfg.NameTemplate, "{namespace}", ns)
	sb := strings.Builder{}
	sb.WriteString("# 自动生成 NetworkPolicy (C5 PolicyGen)\n")
	sb.WriteString("# 来源: 24h 流量观察, 仅 allow 已观察到的链路\n")
	sb.WriteString("apiVersion: networking.k8s.io/v1\n")
	sb.WriteString("kind: NetworkPolicy\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", ns))
	sb.WriteString("spec:\n")
	sb.WriteString("  podSelector: {}\n") // 应用到 ns 内所有 pod
	sb.WriteString("  policyTypes:\n")
	sb.WriteString("    - Ingress\n")
	if cfg.IncludeEgress {
		sb.WriteString("    - Egress\n")
	}
	sb.WriteString("  ingress:\n")

	// 按 (fromNs, fromLabels) 聚合 port 列表
	type fromKey struct {
		ns, labelsKey string
	}
	fromGroups := map[fromKey][]ingressRule{}
	for _, r := range rules {
		k := fromKey{ns: r.fromNs, labelsKey: labelsKey(r.fromLabels)}
		fromGroups[k] = append(fromGroups[k], r)
	}
	// 稳定排序
	var keys []fromKey
	for k := range fromGroups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ns != keys[j].ns {
			return keys[i].ns < keys[j].ns
		}
		return keys[i].labelsKey < keys[j].labelsKey
	})

	for _, k := range keys {
		group := fromGroups[k]
		sb.WriteString("    - from:\n")
		if k.ns == ns {
			// 同 ns: 用 podSelector
			sb.WriteString("        - podSelector:\n")
			sb.WriteString("            matchLabels:\n")
			writeLabels(&sb, group[0].fromLabels, 14)
		} else {
			// 跨 ns: namespaceSelector + podSelector
			sb.WriteString("        - namespaceSelector:\n")
			sb.WriteString("            matchLabels:\n")
			sb.WriteString(fmt.Sprintf("              kubernetes.io/metadata.name: %s\n", k.ns))
			sb.WriteString("          podSelector:\n")
			sb.WriteString("            matchLabels:\n")
			writeLabels(&sb, group[0].fromLabels, 14)
		}
		// ports
		sb.WriteString("      ports:\n")
		seen := map[string]bool{}
		for _, r := range group {
			key := r.proto + ":" + r.port
			if seen[key] {
				continue
			}
			seen[key] = true
			sb.WriteString(fmt.Sprintf("        - protocol: %s\n", r.proto))
			sb.WriteString(fmt.Sprintf("          port: %s\n", r.port))
		}
	}
	return sb.String()
}

func writeLabels(sb *strings.Builder, labels map[string]string, indent int) {
	if len(labels) == 0 {
		// 通配: 任何 pod
		pad := strings.Repeat(" ", indent)
		sb.WriteString(pad + "_any: \"true\"\n")
		return
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pad := strings.Repeat(" ", indent)
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("%s%s: %s\n", pad, k, labels[k]))
	}
}

// labelsKey 把 map 序列化成稳定 key.
func labelsKey(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(m[k])
		sb.WriteByte(',')
	}
	return sb.String()
}

// parseLabelsKey 反向解析.
func parseLabelsKey(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	for _, kv := range strings.Split(s, ",") {
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		out[kv[:eq]] = kv[eq+1:]
	}
	return out
}

// DefaultDenyPolicy 给指定 ns 生成 default-deny-all yaml.
func DefaultDenyPolicy(ns string) string {
	return fmt.Sprintf(`# Default deny-all (C5 PolicyGen)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
`, ns)
}
