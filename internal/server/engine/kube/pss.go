// Package kube — Pod Security Standards 检查器 (B10).
//
// K8s 官方 3 个 Profile (PSS v1.27):
//   - Privileged: 完全不限制 (开发/测试)
//   - Baseline: 防最常见已知特权升级 (生产最低线)
//   - Restricted: 当前 PSS 最严 (CIS recommended)
//
// 本 checker 给定 PodSpec 返当前等级 + 违例列表.
//
// 参考: https://kubernetes.io/docs/concepts/security/pod-security-standards/
package kube

import (
	"strings"
)

// Profile PSS 等级.
type Profile string

const (
	ProfilePrivileged Profile = "privileged"
	ProfileBaseline   Profile = "baseline"
	ProfileRestricted Profile = "restricted"
)

// Violation 单条违例.
type Violation struct {
	Field    string // 字段路径, e.g. "spec.containers[0].securityContext.privileged"
	Reason   string
	Severity string // critical / high / medium
}

// PodSpec 简化的 Pod 安全字段视图.
//
// 不引 k8s.io/api 重型包, 调用方自行从 corev1.Pod 抽取后传入.
type PodSpec struct {
	HostNetwork    bool
	HostPID        bool
	HostIPC        bool
	HostUsers      *bool // nil = 集群默认
	Containers     []Container
	InitContainers []Container
	Volumes        []Volume
}

// Container 安全字段.
type Container struct {
	Name                     string
	Image                    string
	Privileged               bool
	AllowPrivilegeEscalation *bool
	RunAsUser                *int64
	RunAsNonRoot             *bool
	ReadOnlyRootFilesystem   *bool
	AddedCapabilities        []string
	DroppedCapabilities      []string
	SELinuxOptions           map[string]string
	SeccompProfile           string // RuntimeDefault / Localhost / Unconfined / ""
	HostPorts                []int32
}

// Volume 卷.
type Volume struct {
	Name string
	Type string // hostPath / emptyDir / configMap / secret / pvc / ...
}

// Check 给定 PodSpec 返最高可达等级 + 所有违例.
//
// 算法: 假设 Restricted, 找所有违例; 没 Restricted 违例 → Restricted;
// 有 → 降到 Baseline, 再检; 仍有 → Privileged.
func Check(spec PodSpec) (Profile, []Violation) {
	violations := []Violation{}
	violations = append(violations, checkBaseline(spec)...)
	hasBaseline := len(violations) > 0
	restrictedExtra := checkRestrictedExtra(spec)
	if !hasBaseline && len(restrictedExtra) == 0 {
		return ProfileRestricted, nil
	}
	if !hasBaseline {
		return ProfileBaseline, restrictedExtra
	}
	all := append(violations, restrictedExtra...)
	return ProfilePrivileged, all
}

// checkBaseline 检 Baseline 违例 (任何一条违例 = 无法达到 Baseline).
func checkBaseline(spec PodSpec) []Violation {
	var vs []Violation
	if spec.HostNetwork {
		vs = append(vs, Violation{Field: "spec.hostNetwork", Reason: "host network sharing", Severity: "critical"})
	}
	if spec.HostPID {
		vs = append(vs, Violation{Field: "spec.hostPID", Reason: "host PID sharing", Severity: "critical"})
	}
	if spec.HostIPC {
		vs = append(vs, Violation{Field: "spec.hostIPC", Reason: "host IPC sharing", Severity: "critical"})
	}
	for i, v := range spec.Volumes {
		if v.Type == "hostPath" {
			vs = append(vs, Violation{
				Field:    "spec.volumes[" + itoa(i) + "].hostPath",
				Reason:   "hostPath volume",
				Severity: "high",
			})
		}
	}
	for i, c := range allContainers(spec) {
		prefix := containerFieldPrefix(spec, c, i)
		if c.Privileged {
			vs = append(vs, Violation{Field: prefix + ".securityContext.privileged", Reason: "privileged container", Severity: "critical"})
		}
		for _, cap := range c.AddedCapabilities {
			if isDangerousCap(cap) {
				vs = append(vs, Violation{
					Field:    prefix + ".securityContext.capabilities.add",
					Reason:   "dangerous capability: " + cap,
					Severity: "high",
				})
			}
		}
		for _, hp := range c.HostPorts {
			if hp != 0 {
				vs = append(vs, Violation{Field: prefix + ".ports.hostPort", Reason: "host port exposure", Severity: "medium"})
			}
		}
		if c.SeccompProfile == "Unconfined" {
			vs = append(vs, Violation{Field: prefix + ".securityContext.seccompProfile", Reason: "Unconfined seccomp", Severity: "high"})
		}
	}
	return vs
}

// checkRestrictedExtra Restricted 比 Baseline 额外的限制.
func checkRestrictedExtra(spec PodSpec) []Violation {
	var vs []Violation
	for i, c := range allContainers(spec) {
		prefix := containerFieldPrefix(spec, c, i)
		// allowPrivilegeEscalation 必须显式 false
		if c.AllowPrivilegeEscalation == nil || *c.AllowPrivilegeEscalation {
			vs = append(vs, Violation{
				Field:    prefix + ".securityContext.allowPrivilegeEscalation",
				Reason:   "allowPrivilegeEscalation must be false",
				Severity: "high",
			})
		}
		// runAsNonRoot 必须 true 或 runAsUser != 0
		isNonRoot := (c.RunAsNonRoot != nil && *c.RunAsNonRoot) ||
			(c.RunAsUser != nil && *c.RunAsUser != 0)
		if !isNonRoot {
			vs = append(vs, Violation{
				Field:    prefix + ".securityContext.runAsNonRoot",
				Reason:   "must run as non-root",
				Severity: "high",
			})
		}
		// seccomp profile 必须 RuntimeDefault 或 Localhost (不能空 / Unconfined)
		if c.SeccompProfile == "" || c.SeccompProfile == "Unconfined" {
			vs = append(vs, Violation{
				Field:    prefix + ".securityContext.seccompProfile",
				Reason:   "seccompProfile must be RuntimeDefault or Localhost",
				Severity: "medium",
			})
		}
		// 必须 drop ALL caps
		droppedAll := false
		for _, d := range c.DroppedCapabilities {
			if strings.ToUpper(d) == "ALL" {
				droppedAll = true
				break
			}
		}
		if !droppedAll {
			vs = append(vs, Violation{
				Field:    prefix + ".securityContext.capabilities.drop",
				Reason:   "must drop ALL capabilities",
				Severity: "medium",
			})
		}
	}
	return vs
}

func allContainers(spec PodSpec) []Container {
	out := make([]Container, 0, len(spec.Containers)+len(spec.InitContainers))
	out = append(out, spec.Containers...)
	out = append(out, spec.InitContainers...)
	return out
}

func containerFieldPrefix(_ PodSpec, c Container, idx int) string {
	return "spec.containers[" + itoa(idx) + "/" + c.Name + "]"
}

// isDangerousCap PSS Baseline 禁的 cap 列表 (CIS 推荐).
func isDangerousCap(cap string) bool {
	dangerous := []string{
		"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
		"SYS_RAWIO", "SYS_TIME", "DAC_READ_SEARCH", "MAC_OVERRIDE",
		"MAC_ADMIN", "AUDIT_CONTROL", "SETFCAP", "BPF",
	}
	upper := strings.ToUpper(cap)
	upper = strings.TrimPrefix(upper, "CAP_")
	for _, d := range dangerous {
		if upper == d {
			return true
		}
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
