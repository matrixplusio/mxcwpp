package biz

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ===== 网络安全检查 (002, 029-035) =====

func (c *KubeBaselineChecker) checkNetworkPolicy(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	systemNS := map[string]bool{"kube-system": true, "kube-public": true, "kube-node-lease": true, "default": true}
	var affected model.AffectedResources
	for _, ns := range namespaces.Items {
		if systemNS[ns.Name] {
			continue
		}
		policies, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil || len(policies.Items) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Namespace", Name: ns.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkDefaultDenyIngress(ctx context.Context) (string, model.AffectedResources) {
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
		if isSystemNamespace(ns.Name) {
			continue
		}
		policies, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		hasDefaultDeny := false
		for _, pol := range policies.Items {
			// 默认拒绝入站：podSelector 为空 + policyTypes 包含 Ingress + ingress 规则为空
			if len(pol.Spec.PodSelector.MatchLabels) == 0 && len(pol.Spec.PodSelector.MatchExpressions) == 0 {
				for _, pt := range pol.Spec.PolicyTypes {
					if pt == networkingv1.PolicyTypeIngress && len(pol.Spec.Ingress) == 0 {
						hasDefaultDeny = true
						break
					}
				}
			}
			if hasDefaultDeny {
				break
			}
		}
		if !hasDefaultDeny {
			affected = append(affected, model.AffectedResource{Kind: "Namespace", Name: ns.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkDefaultDenyEgress(ctx context.Context) (string, model.AffectedResources) {
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
		if isSystemNamespace(ns.Name) {
			continue
		}
		policies, err := clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		hasDefaultDeny := false
		for _, pol := range policies.Items {
			if len(pol.Spec.PodSelector.MatchLabels) == 0 && len(pol.Spec.PodSelector.MatchExpressions) == 0 {
				for _, pt := range pol.Spec.PolicyTypes {
					if pt == networkingv1.PolicyTypeEgress && len(pol.Spec.Egress) == 0 {
						hasDefaultDeny = true
						break
					}
				}
			}
			if hasDefaultDeny {
				break
			}
		}
		if !hasDefaultDeny {
			affected = append(affected, model.AffectedResource{Kind: "Namespace", Name: ns.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNodePortServices(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, svc := range services.Items {
		if isSystemNamespace(svc.Namespace) {
			continue
		}
		if svc.Spec.Type == corev1.ServiceTypeNodePort {
			affected = append(affected, model.AffectedResource{Kind: "Service", Name: svc.Name, Namespace: svc.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkLoadBalancerServices(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, svc := range services.Items {
		if isSystemNamespace(svc.Namespace) {
			continue
		}
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			affected = append(affected, model.AffectedResource{Kind: "Service", Name: svc.Name, Namespace: svc.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkExternalIPsServices(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, svc := range services.Items {
		if len(svc.Spec.ExternalIPs) > 0 {
			affected = append(affected, model.AffectedResource{
				Kind: "Service", Name: fmt.Sprintf("%s (externalIPs: %s)", svc.Name, strings.Join(svc.Spec.ExternalIPs, ",")), Namespace: svc.Namespace,
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkIngressTLS(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	ingresses, err := clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, ing := range ingresses.Items {
		if len(ing.Spec.TLS) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Ingress", Name: ing.Name, Namespace: ing.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkServiceWithoutSelector(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, svc := range services.Items {
		if isSystemNamespace(svc.Namespace) {
			continue
		}
		// ExternalName 类型 Service 没有 selector 是正常的
		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		if len(svc.Spec.Selector) == 0 {
			affected = append(affected, model.AffectedResource{Kind: "Service", Name: svc.Name, Namespace: svc.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

// ===== 密钥与配置检查 (036-043) =====

func (c *KubeBaselineChecker) checkSecretsInEnv(ctx context.Context) (string, model.AffectedResources) {
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
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					affected = append(affected, model.AffectedResource{
						Kind: "Pod", Name: fmt.Sprintf("%s/%s (env:%s)", pod.Name, container.Name, env.Name), Namespace: pod.Namespace,
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

func (c *KubeBaselineChecker) checkDefaultNamespaceUsage(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		// 跳过 kubernetes 系统 Pod
		if pod.Name == "kubernetes" {
			continue
		}
		affected = append(affected, model.AffectedResource{Kind: "Pod", Name: pod.Name, Namespace: "default"})
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkTillerDeployment(ctx context.Context) (string, model.AffectedResources) {
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
		if dep.Name == "tiller-deploy" || strings.HasPrefix(dep.Name, "tiller") {
			affected = append(affected, model.AffectedResource{Kind: "Deployment", Name: dep.Name, Namespace: dep.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkLargeSecrets(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	const maxSize = 1024 * 1024 // 1MB
	var affected model.AffectedResources
	for _, secret := range secrets.Items {
		totalSize := 0
		for _, v := range secret.Data {
			totalSize += len(v)
		}
		if totalSize > maxSize {
			affected = append(affected, model.AffectedResource{
				Kind: "Secret", Name: fmt.Sprintf("%s (%dKB)", secret.Name, totalSize/1024), Namespace: secret.Namespace,
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkLargeConfigMaps(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	configMaps, err := clientset.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	const maxSize = 1024 * 1024 // 1MB
	var affected model.AffectedResources
	for _, cm := range configMaps.Items {
		if isSystemNamespace(cm.Namespace) {
			continue
		}
		totalSize := 0
		for _, v := range cm.Data {
			totalSize += len(v)
		}
		for _, v := range cm.BinaryData {
			totalSize += len(v)
		}
		if totalSize > maxSize {
			affected = append(affected, model.AffectedResource{
				Kind: "ConfigMap", Name: fmt.Sprintf("%s (%dKB)", cm.Name, totalSize/1024), Namespace: cm.Namespace,
			})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkNamespaceLabels(ctx context.Context) (string, model.AffectedResources) {
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
		// 检查是否至少有一个自定义标签（排除 kubernetes.io 系统标签）
		hasCustomLabel := false
		for k := range ns.Labels {
			if !strings.Contains(k, "kubernetes.io") && k != "name" {
				hasCustomLabel = true
				break
			}
		}
		if !hasCustomLabel {
			affected = append(affected, model.AffectedResource{Kind: "Namespace", Name: ns.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkSATokenSecrets(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, secret := range secrets.Items {
		if isSystemNamespace(secret.Namespace) {
			continue
		}
		if secret.Type == corev1.SecretTypeServiceAccountToken {
			affected = append(affected, model.AffectedResource{Kind: "Secret", Name: secret.Name, Namespace: secret.Namespace})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkPlaintextPasswords(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	sensitiveKeys := []string{"password", "passwd", "secret", "token", "api_key", "apikey", "private_key"}
	var affected model.AffectedResources
	for _, pod := range pods.Items {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if env.Value == "" || env.ValueFrom != nil {
					continue
				}
				envLower := strings.ToLower(env.Name)
				for _, key := range sensitiveKeys {
					if strings.Contains(envLower, key) {
						affected = append(affected, model.AffectedResource{
							Kind: "Pod", Name: fmt.Sprintf("%s/%s (env:%s)", pod.Name, container.Name, env.Name), Namespace: pod.Namespace,
						})
						break
					}
				}
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}
