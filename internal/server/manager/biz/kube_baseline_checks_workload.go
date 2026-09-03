package biz

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ===== 工作负载安全检查 (044-055) =====

func (c *KubeBaselineChecker) checkSingleReplicaDeployments(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, dep := range deployments.Items {
		if isSystemNamespace(dep.Namespace) {
			continue
		}
		if dep.Spec.Replicas != nil && *dep.Spec.Replicas <= 1 {
			affected = append(affected, model.AffectedResource{
				Kind: "Deployment", Name: fmt.Sprintf("%s (replicas:%d)", dep.Name, *dep.Spec.Replicas), Namespace: dep.Namespace,
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkPDBCoverage(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	pdbs, err := clientset.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, dep := range deployments.Items {
		if isSystemNamespace(dep.Namespace) {
			continue
		}
		// 只检查多副本 Deployment
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas <= 1 {
			continue
		}
		// 检查是否有 PDB 的 selector 覆盖该 Deployment 的 Pod
		covered := false
		for _, pdb := range pdbs.Items {
			if pdb.Namespace != dep.Namespace {
				continue
			}
			if pdb.Spec.Selector == nil {
				continue
			}
			// PDB selector 的所有 matchLabels 必须是 Deployment selector 的子集
			if dep.Spec.Selector != nil && labelsMatch(pdb.Spec.Selector.MatchLabels, dep.Spec.Selector.MatchLabels) {
				covered = true
				break
			}
		}
		if !covered {
			affected = append(affected, model.AffectedResource{Kind: "Deployment", Name: dep.Name, Namespace: dep.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkCronJobDeadline(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	cronJobs, err := clientset.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, cj := range cronJobs.Items {
		if isSystemNamespace(cj.Namespace) {
			continue
		}
		if cj.Spec.JobTemplate.Spec.ActiveDeadlineSeconds == nil {
			affected = append(affected, model.AffectedResource{Kind: "CronJob", Name: cj.Name, Namespace: cj.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkUntrustedRegistries(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	// 可信仓库前缀（可根据企业实际情况配置）
	trustedPrefixes := []string{
		"registry.k8s.io/", "docker.io/library/", "gcr.io/", "ghcr.io/",
		"quay.io/", "mcr.microsoft.com/", "registry.cn-",
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			image := container.Image
			trusted := false
			for _, prefix := range trustedPrefixes {
				if strings.HasPrefix(image, prefix) {
					trusted = true
					break
				}
			}
			// 不含 / 的镜像（如 nginx）来自 Docker Hub 官方库
			if !strings.Contains(image, "/") {
				trusted = true
			}
			if !trusted {
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

func (c *KubeBaselineChecker) checkHPAMinReplicas(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	hpas, err := clientset.AutoscalingV1().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, hpa := range hpas.Items {
		if isSystemNamespace(hpa.Namespace) {
			continue
		}
		if hpa.Spec.MinReplicas != nil && *hpa.Spec.MinReplicas <= 1 {
			affected = append(affected, model.AffectedResource{
				Kind: "HPA", Name: fmt.Sprintf("%s (min:%d)", hpa.Name, *hpa.Spec.MinReplicas), Namespace: hpa.Namespace,
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkDaemonSetResourceLimits(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	daemonSets, err := clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, ds := range daemonSets.Items {
		if isSystemNamespace(ds.Namespace) {
			continue
		}
		for _, container := range ds.Spec.Template.Spec.Containers {
			cpuMissing := container.Resources.Limits.Cpu() == nil || container.Resources.Limits.Cpu().IsZero()
			memMissing := container.Resources.Limits.Memory() == nil || container.Resources.Limits.Memory().IsZero()
			if cpuMissing || memMissing {
				affected = append(affected, model.AffectedResource{
					Kind: "DaemonSet", Name: fmt.Sprintf("%s/%s", ds.Name, container.Name), Namespace: ds.Namespace,
				})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkJobBackoffLimit(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	jobs, err := clientset.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, job := range jobs.Items {
		if isSystemNamespace(job.Namespace) {
			continue
		}
		// K8s 默认 backoffLimit=6，但显式设置更好
		if job.Spec.BackoffLimit == nil {
			affected = append(affected, model.AffectedResource{Kind: "Job", Name: job.Name, Namespace: job.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkDeploymentStrategy(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, dep := range deployments.Items {
		if isSystemNamespace(dep.Namespace) {
			continue
		}
		if string(dep.Spec.Strategy.Type) == "Recreate" {
			affected = append(affected, model.AffectedResource{
				Kind: "Deployment", Name: fmt.Sprintf("%s (Recreate)", dep.Name), Namespace: dep.Namespace,
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkStatefulSetStorage(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	statefulSets, err := clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, sts := range statefulSets.Items {
		if isSystemNamespace(sts.Namespace) {
			continue
		}
		if len(sts.Spec.VolumeClaimTemplates) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "StatefulSet", Name: sts.Name, Namespace: sts.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkPodAntiAffinity(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, dep := range deployments.Items {
		if isSystemNamespace(dep.Namespace) {
			continue
		}
		// 只检查多副本 Deployment
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas <= 1 {
			continue
		}
		affinity := dep.Spec.Template.Spec.Affinity
		if affinity == nil || affinity.PodAntiAffinity == nil {
			affected = append(affected, model.AffectedResource{Kind: "Deployment", Name: dep.Name, Namespace: dep.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkTopologySpreadConstraints(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, dep := range deployments.Items {
		if isSystemNamespace(dep.Namespace) {
			continue
		}
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas <= 1 {
			continue
		}
		if len(dep.Spec.Template.Spec.TopologySpreadConstraints) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Deployment", Name: dep.Name, Namespace: dep.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkDeploymentHPA(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	hpas, err := clientset.AutoscalingV1().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	// 构建 HPA 目标索引
	hpaTargets := make(map[string]bool)
	for _, hpa := range hpas.Items {
		key := fmt.Sprintf("%s/%s", hpa.Namespace, hpa.Spec.ScaleTargetRef.Name)
		hpaTargets[key] = true
	}
	var affected model.AffectedResources
	for _, dep := range deployments.Items {
		if isSystemNamespace(dep.Namespace) {
			continue
		}
		key := fmt.Sprintf("%s/%s", dep.Namespace, dep.Name)
		if !hpaTargets[key] {
			affected = append(affected, model.AffectedResource{Kind: "Deployment", Name: dep.Name, Namespace: dep.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

// labelsMatch 检查 pdbLabels 是否为 depLabels 的子集
// 即 PDB selector 覆盖了 Deployment selector 对应的 Pod
func labelsMatch(pdbLabels, depLabels map[string]string) bool {
	if len(pdbLabels) == 0 {
		return false
	}
	for k, v := range pdbLabels {
		if depLabels[k] != v {
			return false
		}
	}
	return true
}
