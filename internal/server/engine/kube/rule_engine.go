package kube

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// KubeRuleEngine CEL-based K8s 基线规则引擎
type KubeRuleEngine struct {
	env    *cel.Env
	logger *zap.Logger
}

// resourceItem 保存 K8s 资源的 map 表示和元信息
type resourceItem struct {
	Data        map[string]any
	Name        string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
	Kind        string
}

// NewKubeRuleEngine 创建 K8s CEL 规则引擎
func NewKubeRuleEngine(logger *zap.Logger) (*KubeRuleEngine, error) {
	env, err := newKubeCheckCELEnv()
	if err != nil {
		return nil, fmt.Errorf("初始化 K8s CEL 环境失败: %w", err)
	}
	return &KubeRuleEngine{env: env, logger: logger}, nil
}

// newKubeCheckCELEnv 创建用于 K8s 基线检查的 CEL 环境
func newKubeCheckCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("resource", cel.DynType),
		cel.Variable("name", cel.StringType),
		cel.Variable("namespace", cel.StringType),
		cel.Variable("labels", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("annotations", cel.MapType(cel.StringType, cel.StringType)),
	)
}

// CompileExpression 编译并验证 CEL 表达式（供 API 层调用）
func (e *KubeRuleEngine) CompileExpression(expression string) error {
	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("编译错误: %w", issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return fmt.Errorf("表达式返回类型必须为 bool，实际为 %s", ast.OutputType())
	}
	return nil
}

// EvaluateRule 对指定集群执行 CEL 规则检查
func (e *KubeRuleEngine) EvaluateRule(ctx context.Context, clientset *kubernetes.Clientset, config *model.KubeCheckConfig) (string, model.AffectedResources) {
	// 编译表达式
	ast, issues := e.env.Compile(config.Expression)
	if issues != nil && issues.Err() != nil {
		e.logger.Error("CEL 表达式编译失败", zap.String("expression", config.Expression), zap.Error(issues.Err()))
		return "error", nil
	}
	program, err := e.env.Program(ast)
	if err != nil {
		e.logger.Error("CEL Program 创建失败", zap.Error(err))
		return "error", nil
	}

	// 获取资源
	items, err := e.fetchResources(ctx, clientset, config)
	if err != nil {
		e.logger.Error("获取 K8s 资源失败", zap.String("resource", config.ResourceType), zap.Error(err))
		return "error", nil
	}

	// 评估每个资源
	var matched model.AffectedResources
	for _, item := range items {
		activation := map[string]any{
			"resource":    item.Data,
			"name":        item.Name,
			"namespace":   item.Namespace,
			"labels":      item.Labels,
			"annotations": item.Annotations,
		}

		out, _, err := program.Eval(activation)
		if err != nil {
			e.logger.Debug("CEL 表达式求值错误", zap.String("resource", item.Name), zap.Error(err))
			continue
		}

		if out.Value() == true {
			matched = append(matched, model.AffectedResource{
				Kind:      item.Kind,
				Name:      item.Name,
				Namespace: item.Namespace,
			})
		}
	}

	// 根据匹配策略判定结果
	switch config.MatchPolicy {
	case "any_match_fail":
		if len(matched) > 0 {
			return "fail", matched
		}
		return "pass", nil
	case "no_match_fail":
		if len(matched) == 0 {
			return "fail", nil
		}
		return "pass", nil
	default:
		// 默认 any_match_fail
		if len(matched) > 0 {
			return "fail", matched
		}
		return "pass", nil
	}
}

// fetchResources 按类型和范围获取 K8s 资源，转为 map[string]any
func (e *KubeRuleEngine) fetchResources(ctx context.Context, clientset *kubernetes.Clientset, config *model.KubeCheckConfig) ([]resourceItem, error) {
	ns := resolveNamespace(config.Namespace)
	filterNonSystem := config.Namespace == "!system"

	listOpts := metav1.ListOptions{}

	var rawItems []any
	var kind string

	switch config.ResourceType {
	// Core
	case "pods":
		kind = "Pod"
		list, err := clientset.CoreV1().Pods(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "services":
		kind = "Service"
		list, err := clientset.CoreV1().Services(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "namespaces":
		kind = "Namespace"
		list, err := clientset.CoreV1().Namespaces().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "nodes":
		kind = "Node"
		list, err := clientset.CoreV1().Nodes().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "secrets":
		kind = "Secret"
		list, err := clientset.CoreV1().Secrets(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "configmaps":
		kind = "ConfigMap"
		list, err := clientset.CoreV1().ConfigMaps(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "serviceaccounts":
		kind = "ServiceAccount"
		list, err := clientset.CoreV1().ServiceAccounts(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "persistentvolumes":
		kind = "PersistentVolume"
		list, err := clientset.CoreV1().PersistentVolumes().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	// Apps
	case "deployments":
		kind = "Deployment"
		list, err := clientset.AppsV1().Deployments(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "statefulsets":
		kind = "StatefulSet"
		list, err := clientset.AppsV1().StatefulSets(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "daemonsets":
		kind = "DaemonSet"
		list, err := clientset.AppsV1().DaemonSets(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	// RBAC
	case "clusterroles":
		kind = "ClusterRole"
		list, err := clientset.RbacV1().ClusterRoles().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "clusterrolebindings":
		kind = "ClusterRoleBinding"
		list, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "roles":
		kind = "Role"
		list, err := clientset.RbacV1().Roles(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "rolebindings":
		kind = "RoleBinding"
		list, err := clientset.RbacV1().RoleBindings(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	// Networking
	case "networkpolicies":
		kind = "NetworkPolicy"
		list, err := clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "ingresses":
		kind = "Ingress"
		list, err := clientset.NetworkingV1().Ingresses(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	// Batch
	case "cronjobs":
		kind = "CronJob"
		list, err := clientset.BatchV1().CronJobs(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "jobs":
		kind = "Job"
		list, err := clientset.BatchV1().Jobs(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	// Storage
	case "storageclasses":
		kind = "StorageClass"
		list, err := clientset.StorageV1().StorageClasses().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	// Autoscaling
	case "horizontalpodautoscalers":
		kind = "HorizontalPodAutoscaler"
		list, err := clientset.AutoscalingV1().HorizontalPodAutoscalers(ns).List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	// AdmissionRegistration
	case "validatingwebhookconfigurations":
		kind = "ValidatingWebhookConfiguration"
		list, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	case "mutatingwebhookconfigurations":
		kind = "MutatingWebhookConfiguration"
		list, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, listOpts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rawItems = append(rawItems, &list.Items[i])
		}
	default:
		return nil, fmt.Errorf("不支持的资源类型: %s", config.ResourceType)
	}

	// 转换为 resourceItem
	var items []resourceItem
	for _, raw := range rawItems {
		item, err := toResourceItem(raw, kind)
		if err != nil {
			e.logger.Debug("资源转换失败", zap.Error(err))
			continue
		}
		// 过滤系统命名空间
		if filterNonSystem && isSystemNamespace(item.Namespace) {
			continue
		}
		items = append(items, item)
	}

	return items, nil
}

// resolveNamespace 解析命名空间配置
func resolveNamespace(ns string) string {
	switch ns {
	case "*", "!system":
		return "" // 所有命名空间
	default:
		return ns // 特定命名空间或空（集群级）
	}
}

// toResourceItem 将 K8s 资源对象转为 resourceItem
func toResourceItem(obj any, kind string) (resourceItem, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return resourceItem{}, fmt.Errorf("JSON 序列化失败: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return resourceItem{}, fmt.Errorf("JSON 反序列化失败: %w", err)
	}

	item := resourceItem{
		Data:        m,
		Kind:        kind,
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
	}

	// 提取 metadata
	if metadata, ok := m["metadata"].(map[string]any); ok {
		if name, ok := metadata["name"].(string); ok {
			item.Name = name
		}
		if ns, ok := metadata["namespace"].(string); ok {
			item.Namespace = ns
		}
		if labels, ok := metadata["labels"].(map[string]any); ok {
			for k, v := range labels {
				if s, ok := v.(string); ok {
					item.Labels[k] = s
				}
			}
		}
		if annotations, ok := metadata["annotations"].(map[string]any); ok {
			for k, v := range annotations {
				if s, ok := v.(string); ok {
					item.Annotations[k] = s
				}
			}
		}
	}

	return item, nil
}
