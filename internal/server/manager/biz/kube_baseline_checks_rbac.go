package biz

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// ===== RBAC 安全检查 (001, 005, 006-012) =====

func (c *KubeBaselineChecker) checkAnonymousRBAC(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, crb := range crbs.Items {
		for _, subject := range crb.Subjects {
			if subject.Name == "system:anonymous" || subject.Name == "system:unauthenticated" {
				affected = append(affected, model.AffectedResource{Kind: "ClusterRoleBinding", Name: crb.Name})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkDefaultServiceAccount(ctx context.Context) (string, model.AffectedResources) {
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
		if pod.Spec.ServiceAccountName == "default" {
			mount := true
			if pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken {
				mount = false
			}
			if mount {
				affected = append(affected, model.AffectedResource{Kind: "Pod", Name: pod.Name, Namespace: pod.Namespace})
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkClusterAdminBinding(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	// 系统默认的 cluster-admin 绑定白名单
	systemBindings := map[string]bool{
		"cluster-admin": true,
	}
	var affected model.AffectedResources
	for _, crb := range crbs.Items {
		if systemBindings[crb.Name] {
			continue
		}
		if crb.RoleRef.Kind == "ClusterRole" && crb.RoleRef.Name == "cluster-admin" {
			affected = append(affected, model.AffectedResource{Kind: "ClusterRoleBinding", Name: crb.Name})
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkWildcardRBAC(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	roles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	// 系统内置角色白名单
	systemRoles := map[string]bool{
		"cluster-admin": true, "admin": true, "edit": true, "view": true,
		"system:controller:clusterrole-aggregation-controller": true,
	}
	var affected model.AffectedResources
	for _, role := range roles.Items {
		if systemRoles[role.Name] || strings.HasPrefix(role.Name, "system:") {
			continue
		}
		for _, rule := range role.Rules {
			hasWildcard := false
			for _, verb := range rule.Verbs {
				if verb == "*" {
					hasWildcard = true
					break
				}
			}
			if !hasWildcard {
				for _, res := range rule.Resources {
					if res == "*" {
						hasWildcard = true
						break
					}
				}
			}
			if hasWildcard {
				affected = append(affected, model.AffectedResource{Kind: "ClusterRole", Name: role.Name})
				break
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkExecAttachRBAC(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	roles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, role := range roles.Items {
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}
		for _, rule := range role.Rules {
			for _, res := range rule.Resources {
				if res == "pods/exec" || res == "pods/attach" {
					affected = append(affected, model.AffectedResource{Kind: "ClusterRole", Name: role.Name})
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

func (c *KubeBaselineChecker) checkSecretsAccessRBAC(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	roles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	systemRoles := map[string]bool{
		"cluster-admin": true, "admin": true, "edit": true,
	}
	var affected model.AffectedResources
	for _, role := range roles.Items {
		if systemRoles[role.Name] || strings.HasPrefix(role.Name, "system:") {
			continue
		}
		for _, rule := range role.Rules {
			hasSecrets := false
			for _, res := range rule.Resources {
				if res == "secrets" || res == "*" {
					hasSecrets = true
					break
				}
			}
			if hasSecrets {
				for _, verb := range rule.Verbs {
					if verb == "list" || verb == "get" || verb == "watch" || verb == "*" {
						affected = append(affected, model.AffectedResource{Kind: "ClusterRole", Name: role.Name})
						hasSecrets = false // break outer
						break
					}
				}
			}
			if !hasSecrets {
				break
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}

func (c *KubeBaselineChecker) checkEscalateRBAC(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	roles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	var affected model.AffectedResources
	for _, role := range roles.Items {
		if strings.HasPrefix(role.Name, "system:") || role.Name == "cluster-admin" {
			continue
		}
		for _, rule := range role.Rules {
			for _, verb := range rule.Verbs {
				if verb == "escalate" || verb == "bind" || verb == "impersonate" {
					affected = append(affected, model.AffectedResource{Kind: "ClusterRole", Name: role.Name})
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

func (c *KubeBaselineChecker) checkSAAutoMount(ctx context.Context) (string, model.AffectedResources) {
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
		sas, err := clientset.CoreV1().ServiceAccounts(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, sa := range sas.Items {
			if sa.Name == "default" {
				if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
					affected = append(affected, model.AffectedResource{
						Kind: "ServiceAccount", Name: sa.Name, Namespace: ns.Name,
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

func (c *KubeBaselineChecker) checkSystemMastersBinding(ctx context.Context) (string, model.AffectedResources) {
	clientset := c.getLastClient()
	if clientset == nil {
		return "error", nil
	}
	crbs, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "error", nil
	}
	// 系统默认绑定白名单
	systemBindings := map[string]bool{
		"cluster-admin":             true,
		"system:masters":            true,
		"kubeadm:cluster-admins":    true,
		"eks:cluster-admin-binding": true,
		"aks-cluster-admin-binding": true,
		"gke-cluster-admin-binding": true,
	}
	var affected model.AffectedResources
	for _, crb := range crbs.Items {
		if systemBindings[crb.Name] || strings.HasPrefix(crb.Name, "system:") {
			continue
		}
		for _, subject := range crb.Subjects {
			if subject.Kind == "Group" && subject.Name == "system:masters" {
				affected = append(affected, model.AffectedResource{Kind: "ClusterRoleBinding", Name: crb.Name})
				break
			}
		}
	}
	if len(affected) > 0 {
		return "fail", affected
	}
	return "pass", nil
}
