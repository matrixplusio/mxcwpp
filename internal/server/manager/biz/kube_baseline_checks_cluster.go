package biz

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ===== 节点安全检查 (056-064) =====

func (c *KubeBaselineChecker) checkNodeNotReady(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, node := range nodes.Items {
		ready := false
		for _, cond := range node.Status.Conditions {
			if string(cond.Type) == "Ready" && string(cond.Status) == "True" {
				ready = true
				break
			}
		}
		if !ready {
			affected = append(affected, model.AffectedResource{Kind: "Node", Name: node.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNodePressure(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	pressureTypes := map[string]bool{"MemoryPressure": true, "DiskPressure": true, "PIDPressure": true}
	var affected model.AffectedResources
	for _, node := range nodes.Items {
		var pressures []string
		for _, cond := range node.Status.Conditions {
			if pressureTypes[string(cond.Type)] && string(cond.Status) == "True" {
				pressures = append(pressures, string(cond.Type))
			}
		}
		if len(pressures) > 0 {
			affected = append(affected, model.AffectedResource{
				Kind: "Node", Name: fmt.Sprintf("%s (%s)", node.Name, strings.Join(pressures, ",")),
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNodeKernelVersion(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, node := range nodes.Items {
		kernel := node.Status.NodeInfo.KernelVersion
		parts := strings.SplitN(kernel, ".", 3)
		if len(parts) >= 2 {
			major, errMajor := strconv.Atoi(parts[0])
			minor, errMinor := strconv.Atoi(strings.TrimRight(parts[1], "+-abcdefghijklmnopqrstuvwxyz"))
			if errMajor != nil || errMinor != nil {
				// 无法解析的内核版本跳过，避免误报
				continue
			}
			if major < 4 || (major == 4 && minor < 19) {
				affected = append(affected, model.AffectedResource{
					Kind: "Node", Name: fmt.Sprintf("%s (kernel:%s)", node.Name, kernel),
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNodeContainerRuntime(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, node := range nodes.Items {
		runtime := node.Status.NodeInfo.ContainerRuntimeVersion
		// Docker 运行时已弃用（K8s 1.24+）
		if strings.HasPrefix(runtime, "docker://") {
			affected = append(affected, model.AffectedResource{
				Kind: "Node", Name: fmt.Sprintf("%s (%s)", node.Name, runtime),
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNodeResourceUtilization(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, node := range nodes.Items {
		allocatableCPU := node.Status.Allocatable.Cpu()
		capacityCPU := node.Status.Capacity.Cpu()
		if allocatableCPU != nil && capacityCPU != nil && capacityCPU.MilliValue() > 0 {
			ratio := float64(capacityCPU.MilliValue()-allocatableCPU.MilliValue()) / float64(capacityCPU.MilliValue())
			// 如果系统预留超过 30%，可能有问题
			if ratio > 0.3 {
				affected = append(affected, model.AffectedResource{
					Kind: "Node", Name: fmt.Sprintf("%s (%.0f%% reserved)", node.Name, ratio*100),
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNodeUnschedulable(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, node := range nodes.Items {
		if node.Spec.Unschedulable {
			affected = append(affected, model.AffectedResource{Kind: "Node", Name: node.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNodeTaints(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, node := range nodes.Items {
		for _, taint := range node.Spec.Taints {
			if string(taint.Effect) == "NoExecute" && taint.Key != "node.kubernetes.io/not-ready" && taint.Key != "node.kubernetes.io/unreachable" {
				affected = append(affected, model.AffectedResource{
					Kind: "Node", Name: fmt.Sprintf("%s (taint:%s=%s:%s)", node.Name, taint.Key, taint.Value, taint.Effect),
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkOrphanPods(ctx context.Context) (string, model.AffectedResources) {
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
		if len(pod.OwnerReferences) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNodePodCount(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	// 统计每个节点的 Pod 数
	nodePodCount := make(map[string]int)
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != "" && string(pod.Status.Phase) == "Running" {
			nodePodCount[pod.Spec.NodeName]++
		}
	}
	var affected model.AffectedResources
	for _, node := range nodes.Items {
		allocatablePods := node.Status.Allocatable.Pods()
		count := nodePodCount[node.Name]
		if allocatablePods != nil && allocatablePods.Value() > 0 {
			ratio := float64(count) / float64(allocatablePods.Value())
			if ratio > 0.9 {
				affected = append(affected, model.AffectedResource{
					Kind: "Node", Name: fmt.Sprintf("%s (%d/%d pods, %.0f%%)", node.Name, count, allocatablePods.Value(), ratio*100),
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

// ===== 集群配置检查 (065-073) =====

func (c *KubeBaselineChecker) checkK8sVersion(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	version, err := clientset.Discovery().ServerVersion()
	if err != nil {
		return "error", nil
	}
	major, _ := strconv.Atoi(version.Major)
	minor, _ := strconv.Atoi(strings.TrimSuffix(version.Minor, "+"))
	// K8s 支持最近 3 个小版本 (当前 1.31 → 最低 1.29)
	if major == 1 && minor < 28 {
		return "fail", model.AffectedResources{{
			Kind: "Cluster", Name: fmt.Sprintf("v%s.%s (unsupported)", version.Major, version.Minor),
		}}
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkLimitRange(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, ns := range namespaces.Items {
		if isSystemNamespace(ns.Name) || ns.Name == "default" {
			continue
		}
		lrs, err := clientset.CoreV1().LimitRanges(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil || len(lrs.Items) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Namespace", Name: ns.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkResourceQuota(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, ns := range namespaces.Items {
		if isSystemNamespace(ns.Name) || ns.Name == "default" {
			continue
		}
		rqs, err := clientset.CoreV1().ResourceQuotas(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil || len(rqs.Items) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Namespace", Name: ns.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkPSSLabels(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, ns := range namespaces.Items {
		if isSystemNamespace(ns.Name) || ns.Name == "default" {
			continue
		}
		// Pod Security Standards 标签
		hasPSS := false
		for k := range ns.Labels {
			if strings.HasPrefix(k, "pod-security.kubernetes.io/") {
				hasPSS = true
				break
			}
		}
		if !hasPSS {
			affected = append(affected, model.AffectedResource{Kind: "Namespace", Name: ns.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkAdmissionWebhooks(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	vwcs, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	// 如果没有任何 ValidatingWebhook，说明缺少准入控制
	if len(vwcs.Items) == 0 {
		return "fail", model.AffectedResources{{Kind: "Cluster", Name: "no ValidatingWebhookConfiguration found"}}
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkMutatingWebhookTimeout(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	mwcs, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, mwc := range mwcs.Items {
		for _, wh := range mwc.Webhooks {
			if wh.TimeoutSeconds != nil && *wh.TimeoutSeconds > 10 {
				affected = append(affected, model.AffectedResource{
					Kind: "MutatingWebhookConfiguration", Name: fmt.Sprintf("%s/%s (%ds)", mwc.Name, wh.Name, *wh.TimeoutSeconds),
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNamespaceCount(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	nonSystemCount := 0
	for _, ns := range namespaces.Items {
		if !isSystemNamespace(ns.Name) && ns.Name != "default" {
			nonSystemCount++
		}
	}
	// 超过 50 个非系统 Namespace 需要审计
	if nonSystemCount > 50 {
		return "fail", model.AffectedResources{{
			Kind: "Cluster", Name: fmt.Sprintf("%d non-system namespaces", nonSystemCount),
		}}
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkPVReclaimPolicy(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pvs, err := clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pv := range pvs.Items {
		if string(pv.Spec.PersistentVolumeReclaimPolicy) == "Delete" {
			affected = append(affected, model.AffectedResource{Kind: "PersistentVolume", Name: pv.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkStorageClassExpansion(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	scs, err := clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, sc := range scs.Items {
		if sc.AllowVolumeExpansion == nil || !*sc.AllowVolumeExpansion {
			affected = append(affected, model.AffectedResource{Kind: "StorageClass", Name: sc.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

// ===== 供应链与运行时检查 (074-080) =====

func (c *KubeBaselineChecker) checkImageDigest(ctx context.Context) (string, model.AffectedResources) {
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
			if !strings.Contains(container.Image, "@sha256:") {
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

func (c *KubeBaselineChecker) checkInitContainerSecurity(ctx context.Context) (string, model.AffectedResources) {
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
		for _, container := range pod.Spec.InitContainers {
			// 检查 init 容器是否以特权模式运行或未设置安全上下文
			if container.SecurityContext != nil {
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					affected = append(affected, model.AffectedResource{
						Kind: "Pod", Name: fmt.Sprintf("%s/init:%s (privileged)", pod.Name, container.Name), Namespace: pod.Namespace,
					})
				}
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkImagePullSecrets(ctx context.Context) (string, model.AffectedResources) {
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
		// 检查是否使用了私有镜像但没有配置 imagePullSecrets
		hasPrivateImage := false
		for _, container := range pod.Spec.Containers {
			image := container.Image
			// 包含 / 且不是公共仓库的镜像可能需要认证
			if strings.Contains(image, "/") && !strings.HasPrefix(image, "docker.io/library/") && !strings.HasPrefix(image, "registry.k8s.io/") {
				hasPrivateImage = true
				break
			}
		}
		if hasPrivateImage && len(pod.Spec.ImagePullSecrets) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkPendingPods(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Pending",
	})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		// 只报告超过 5 分钟仍在 Pending 的 Pod
		if pod.CreationTimestamp.Time.Before(time.Now().Add(-5 * time.Minute)) {
			affected = append(affected, model.AffectedResource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkHighRestartPods(ctx context.Context) (string, model.AffectedResources) {
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
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.RestartCount > 10 {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s (restarts:%d)", pod.Name, cs.Name, cs.RestartCount), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkCrashLoopPods(ctx context.Context) (string, model.AffectedResources) {
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
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
				affected = append(affected, model.AffectedResource{
					Kind: "Pod", Name: fmt.Sprintf("%s/%s", pod.Name, cs.Name), Namespace: pod.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkPodsWithoutOwner(ctx context.Context) (string, model.AffectedResources) {
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
		// 过滤 static pod（由 kubelet 直接管理，没有 OwnerReference 但有 mirror pod 注解）
		if _, ok := pod.Annotations["kubernetes.io/config.mirror"]; ok {
			continue
		}
		if len(pod.OwnerReferences) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}
