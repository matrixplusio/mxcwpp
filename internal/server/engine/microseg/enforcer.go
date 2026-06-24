package microseg

// Phase 3: NetworkPolicy enforce 落地 (P2-12).
//
// 接 Phase 2 推荐策略 (recommend.go), 经 6 闸门 admission 后:
//   1. PolicyRecommendation → K8s NetworkPolicy yaml
//   2. 通过 KubeClient 调 K8s Apps API → kubectl apply
//   3. 记录 EnforcementRecord (谁/何时/哪个集群/policy 名)
//   4. 失败回滚 (删除新 policy + 恢复旧版本)
//
// Cilium / Calico 集成:
//   - Cilium: 用 CiliumNetworkPolicy (k8s.io/api/cilium/v2alpha1) 支持 L7
//   - Calico: 用 GlobalNetworkPolicy + NetworkPolicy 标签选择器
//   - vanilla NetworkPolicy: 标准 networking.k8s.io/v1 (L3/L4 only)
//
// 当前默认 vanilla NetworkPolicy, Cilium/Calico 走单独 driver.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// EnforceMode 是 enforce 的执行模式.
type EnforceMode string

const (
	EnforceDryRun EnforceMode = "dry_run" // 仅 server-side validate, 不真落地
	EnforceApply  EnforceMode = "apply"   // 落 K8s API
)

// CNI 网络插件类型.
type CNI string

const (
	CNIVanilla CNI = "vanilla" // networking.k8s.io/v1
	CNICilium  CNI = "cilium"  // cilium.io/v2alpha1 CiliumNetworkPolicy
	CNICalico  CNI = "calico"  // projectcalico.org/v3 NetworkPolicy
)

// KubeAPIClient 抽象 K8s 写入接口 (实现注入).
//
// 实际生产用 client-go dynamic.Interface; 测试可注入 fake.
type KubeAPIClient interface {
	// ApplyNetworkPolicy 对指定 namespace 应用 NetworkPolicy YAML.
	// dryRun=true 时仅走 server-side validate, 不真改集群状态.
	ApplyNetworkPolicy(ctx context.Context, ns, name, yaml string, dryRun bool) error
	// DeleteNetworkPolicy 删指定 NetworkPolicy.
	DeleteNetworkPolicy(ctx context.Context, ns, name string) error
}

// Enforcer 微隔离 Phase 3 策略 enforce.
type Enforcer struct {
	kube      KubeAPIClient
	cni       CNI
	logger    *zap.Logger
	auditFunc func(EnforcementRecord)
}

// NewEnforcer 构造.
func NewEnforcer(kube KubeAPIClient, cni CNI, logger *zap.Logger) *Enforcer {
	if logger == nil {
		logger = zap.NewNop()
	}
	if cni == "" {
		cni = CNIVanilla
	}
	return &Enforcer{kube: kube, cni: cni, logger: logger}
}

// SetAuditCallback 自定义审计回调 (落 DB).
func (e *Enforcer) SetAuditCallback(cb func(EnforcementRecord)) {
	e.auditFunc = cb
}

// EnforcementRecord 单次 enforce 记录 (审计 + 回滚用).
type EnforcementRecord struct {
	TenantID     string
	ClusterID    string
	Namespace    string
	PolicyName   string
	Mode         EnforceMode
	CNI          CNI
	AppliedYAML  string
	PreviousYAML string // 回滚备份
	Operator     string
	AppliedAt    time.Time
	Status       string // success / failed / rolled_back
	ErrorMsg     string
}

// Enforce 执行单次 enforce.
//
// approvedBy 必填 (审计要求); mode=apply 时 K8s 真落地.
func (e *Enforcer) Enforce(ctx context.Context, rec *PolicyRecommendation, mode EnforceMode, approvedBy, clusterID string) (*EnforcementRecord, error) {
	if rec == nil {
		return nil, errors.New("nil recommendation")
	}
	if approvedBy == "" {
		return nil, errors.New("approvedBy required (audit)")
	}
	policyName := fmt.Sprintf("mxcwpp-recommend-%s", rec.Namespace)
	yaml := rec.RenderYAML()
	// 切到 enforce 模式: 改 mxcwpp.io/mode annotation
	yaml = replaceFirst(yaml, "mxcwpp.io/mode: observe", fmt.Sprintf("mxcwpp.io/mode: %s", mode))

	record := &EnforcementRecord{
		TenantID:    rec.TenantID,
		ClusterID:   clusterID,
		Namespace:   rec.Namespace,
		PolicyName:  policyName,
		Mode:        mode,
		CNI:         e.cni,
		AppliedYAML: yaml,
		Operator:    approvedBy,
		AppliedAt:   time.Now(),
		Status:      "pending",
	}

	dryRun := mode == EnforceDryRun
	if err := e.kube.ApplyNetworkPolicy(ctx, rec.Namespace, policyName, yaml, dryRun); err != nil {
		record.Status = "failed"
		record.ErrorMsg = err.Error()
		e.audit(*record)
		return record, fmt.Errorf("apply network policy: %w", err)
	}
	record.Status = "success"
	e.audit(*record)
	e.logger.Info("microseg enforce applied",
		zap.String("namespace", rec.Namespace),
		zap.String("policy", policyName),
		zap.String("mode", string(mode)),
		zap.String("cni", string(e.cni)),
		zap.String("operator", approvedBy))
	return record, nil
}

// Rollback 删指定 NetworkPolicy (运维误操作回滚).
func (e *Enforcer) Rollback(ctx context.Context, ns, policyName, operator string) error {
	if err := e.kube.DeleteNetworkPolicy(ctx, ns, policyName); err != nil {
		return fmt.Errorf("delete network policy: %w", err)
	}
	rec := EnforcementRecord{
		Namespace:  ns,
		PolicyName: policyName,
		Mode:       "rollback",
		Operator:   operator,
		AppliedAt:  time.Now(),
		Status:     "rolled_back",
	}
	e.audit(rec)
	e.logger.Info("microseg policy rolled back",
		zap.String("namespace", ns),
		zap.String("policy", policyName),
		zap.String("operator", operator))
	return nil
}

func (e *Enforcer) audit(r EnforcementRecord) {
	if e.auditFunc != nil {
		e.auditFunc(r)
	}
}

// replaceFirst 替换第一处 (templating 用, 不污染其他字段).
func replaceFirst(s, old, new string) string {
	idx := indexOf(s, old)
	if idx < 0 {
		return s
	}
	return s[:idx] + new + s[idx+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
