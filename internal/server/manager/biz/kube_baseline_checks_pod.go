package biz

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ===== Pod 安全检查 (003, 004, 013-028) =====

func (c *KubeBaselineChecker) checkPrivilegedPods(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				affected = append(affected, model.AffectedResource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace})
				break
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkHostNamespacePods(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC {
			reasons := []string{}
			if pod.Spec.HostNetwork {
				reasons = append(reasons, "hostNetwork")
			}
			if pod.Spec.HostPID {
				reasons = append(reasons, "hostPID")
			}
			if pod.Spec.HostIPC {
				reasons = append(reasons, "hostIPC")
			}
			affected = append(affected, model.AffectedResource{
				Kind: "Pod", Name: pod.Name + " (" + strings.Join(reasons, ",") + ")", Namespace: pod.Namespace,
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkRunAsRoot(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			isRoot := false
			sc := container.SecurityContext
			if sc == nil {
				// 未设置 securityContext，可能以 root 运行
				isRoot = true
			} else if sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
				isRoot = false
			} else if sc.RunAsUser != nil && *sc.RunAsUser == 0 {
				isRoot = true
			} else if sc.RunAsNonRoot == nil && sc.RunAsUser == nil {
				isRoot = true
			}
			if isRoot {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkDangerousCapabilities(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	dangerous := map[string]bool{
		"ALL": true, "SYS_ADMIN": true, "NET_RAW": true, "SYS_PTRACE": true,
		"NET_ADMIN": true, "SYS_MODULE": true, "DAC_OVERRIDE": true,
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
				continue
			}
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if dangerous[string(cap)] {
					affected = append(affected, model.AffectedResource{
						Kind: "Pod", Name: fmt.Sprintf("%s/%s (%s)", pod.Name, container.Name, cap), Namespace: pod.Namespace,
					})
					break
				}
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkReadOnlyRootFilesystem(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkAllowPrivilegeEscalation(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			// 默认 allowPrivilegeEscalation 为 true
			if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkHostPathVolumes(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, vol := range pod.Spec.Volumes {
			if vol.HostPath != nil {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s (hostPath: %s)", pod.Name, vol.HostPath.Path), Namespace: pod.Namespace,
				})
				break
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkDockerSocketMount(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	socketPaths := map[string]bool{
		"/var/run/docker.sock":            true,
		"/run/containerd/containerd.sock": true,
		"/var/run/crio/crio.sock":         true,
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		for _, vol := range pod.Spec.Volumes {
			if vol.HostPath != nil && socketPaths[vol.HostPath.Path] {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s (%s)", pod.Name, vol.HostPath.Path), Namespace: pod.Namespace,
				})
				break
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkSeccompProfile(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		// 检查 Pod 级别
		podHasSeccomp := pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil
		for _, container := range pod.Spec.Containers {
			containerHasSeccomp := container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil
			if !podHasSeccomp && !containerHasSeccomp {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkCPULimits(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if container.Resources.Limits.Cpu() == nil || container.Resources.Limits.Cpu().IsZero() {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkMemoryLimits(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if container.Resources.Limits.Memory() == nil || container.Resources.Limits.Memory().IsZero() {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkResourceRequests(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			cpuMissing := container.Resources.Requests.Cpu() == nil || container.Resources.Requests.Cpu().IsZero()
			memMissing := container.Resources.Requests.Memory() == nil || container.Resources.Requests.Memory().IsZero()
			if cpuMissing || memMissing {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkLivenessProbe(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		// 跳过 Job/CronJob 管理的 Pod（短期任务不需要存活探针）
		if hasOwnerKind(pod.OwnerReferences, "Job") {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if container.LivenessProbe == nil {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkReadinessProbe(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		if hasOwnerKind(pod.OwnerReferences, "Job") {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if container.ReadinessProbe == nil {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkLatestImageTag(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			image := container.Image
			if strings.HasSuffix(image, ":latest") || !strings.Contains(image, ":") {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s (%s)", pod.Name, container.Name, image), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkImagePullPolicy(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if string(container.ImagePullPolicy) != "Always" {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, container.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkHostPort(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.HostPort > 0 {
					affected = append(affected, model.AffectedResource{
						Kind: "Pod", Name: fmt.Sprintf("%s/%s (hostPort:%d)", pod.Name, container.Name, port.HostPort), Namespace: pod.Namespace,
					})
					break
				}
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkAddedCapabilities(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil && len(container.SecurityContext.Capabilities.Add) > 0 {
				caps := make([]string, 0, len(container.SecurityContext.Capabilities.Add))
				for _, cap := range container.SecurityContext.Capabilities.Add {
					caps = append(caps, string(cap))
				}
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s (+%s)", pod.Name, container.Name, strings.Join(caps, ",")), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

// hasOwnerKind 检查 OwnerReferences 中是否包含指定 Kind
func hasOwnerKind(refs []metav1.OwnerReference, kind string) bool {
	for _, ref := range refs {
		if ref.Kind == kind {
			return true
		}
	}
	return false
}
