// Package microseg - KubeAPIClient client-go 实际实现 (P3-15).
//
// 配合 enforcer.go (PR109) 的 KubeAPIClient interface, 走 client-go dynamic
// 把 NetworkPolicy YAML 直接 apply 到 K8s API.
//
// 使用:
//
//	cfg, _ := clientcmd.BuildConfigFromFlags("", "/path/to/kubeconfig")
//	kc, _ := microseg.NewClientGoKubeAPIClient(cfg, logger)
//	enforcer := microseg.NewEnforcer(kc, microseg.CNIVanilla, logger)
//	enforcer.Enforce(ctx, rec, microseg.EnforceApply, "alice@example.com", "cluster-prod")
package microseg

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

// ClientGoKubeAPIClient 走 k8s.io/client-go dynamic.
type ClientGoKubeAPIClient struct {
	cli    dynamic.Interface
	logger *zap.Logger
}

// NewClientGoKubeAPIClient 构造.
func NewClientGoKubeAPIClient(restCfg *rest.Config, logger *zap.Logger) (*ClientGoKubeAPIClient, error) {
	if restCfg == nil {
		return nil, fmt.Errorf("rest config required")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	cli, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	return &ClientGoKubeAPIClient{cli: cli, logger: logger}, nil
}

// netPolGVR networking.k8s.io/v1 NetworkPolicy resource id.
var netPolGVR = schema.GroupVersionResource{
	Group:    "networking.k8s.io",
	Version:  "v1",
	Resource: "networkpolicies",
}

// ApplyNetworkPolicy YAML 解析为 unstructured + Apply/Create.
//
// dryRun=true → DryRunAll 仅 server-side validate.
func (c *ClientGoKubeAPIClient) ApplyNetworkPolicy(ctx context.Context, ns, name, yamlData string, dryRun bool) error {
	// 把 YAML 转 JSON
	jsonData, err := yaml.YAMLToJSON([]byte(yamlData))
	if err != nil {
		return fmt.Errorf("yaml to json: %w", err)
	}
	var u unstructured.Unstructured
	if err := u.UnmarshalJSON(jsonData); err != nil {
		return fmt.Errorf("unmarshal NetworkPolicy: %w", err)
	}
	if u.GetName() == "" {
		u.SetName(name)
	}
	if u.GetNamespace() == "" {
		u.SetNamespace(ns)
	}

	opts := metav1.ApplyOptions{
		FieldManager: "mxcwpp-microseg",
		Force:        true,
	}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}

	_, err = c.cli.Resource(netPolGVR).Namespace(ns).
		Apply(ctx, name, &u, opts)
	if err != nil {
		return fmt.Errorf("apply NetworkPolicy: %w", err)
	}
	c.logger.Info("NetworkPolicy applied via client-go",
		zap.String("namespace", ns),
		zap.String("name", name),
		zap.Bool("dry_run", dryRun))
	return nil
}

// DeleteNetworkPolicy 走 dynamic Delete.
func (c *ClientGoKubeAPIClient) DeleteNetworkPolicy(ctx context.Context, ns, name string) error {
	if err := c.cli.Resource(netPolGVR).Namespace(ns).
		Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("delete NetworkPolicy: %w", err)
	}
	c.logger.Info("NetworkPolicy deleted",
		zap.String("namespace", ns), zap.String("name", name))
	return nil
}

// 编译期 sanity check.
var _ KubeAPIClient = (*ClientGoKubeAPIClient)(nil)
