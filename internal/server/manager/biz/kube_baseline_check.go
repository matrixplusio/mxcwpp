package biz

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// CheckFunc 基线检查函数签名
type CheckFunc func(ctx context.Context, checker *KubeBaselineChecker) (result string, affected model.AffectedResources)

// KubeBaselineChecker K8s CIS 基线检查器
type KubeBaselineChecker struct {
	db             *gorm.DB
	logger         *zap.Logger
	kubeClient     *KubeClientManager
	ruleEngine     *KubeRuleEngine
	checkFuncs     map[string]CheckFunc
	mu             sync.Mutex // 保护 currentCluster 防止并发 RunChecks 竞态
	currentCluster uint
}

// NewKubeBaselineChecker 创建基线检查器
func NewKubeBaselineChecker(db *gorm.DB, logger *zap.Logger, kubeClient *KubeClientManager, ruleEngine *KubeRuleEngine) *KubeBaselineChecker {
	c := &KubeBaselineChecker{
		db:         db,
		logger:     logger,
		kubeClient: kubeClient,
		ruleEngine: ruleEngine,
	}
	c.checkFuncs = c.registerCheckFuncs()
	return c
}

// isSystemNamespace 判断是否为系统 Namespace
func isSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

// registerCheckFuncs 注册所有检查函数（checkID -> Run 函数映射）
func (c *KubeBaselineChecker) registerCheckFuncs() map[string]CheckFunc {
	return map[string]CheckFunc{
		// RBAC 安全
		"CIS-K8S-001": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkAnonymousRBAC(ctx)
		},
		"CIS-K8S-005": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDefaultServiceAccount(ctx)
		},
		"CIS-K8S-006": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkClusterAdminBinding(ctx)
		},
		"CIS-K8S-007": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkWildcardRBAC(ctx)
		},
		"CIS-K8S-008": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkExecAttachRBAC(ctx)
		},
		"CIS-K8S-009": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkSecretsAccessRBAC(ctx)
		},
		"CIS-K8S-010": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkEscalateRBAC(ctx)
		},
		"CIS-K8S-011": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkSAAutoMount(ctx)
		},
		"CIS-K8S-012": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkSystemMastersBinding(ctx)
		},
		// Pod 安全
		"CIS-K8S-003": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkPrivilegedPods(ctx)
		},
		"CIS-K8S-004": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkHostNamespacePods(ctx)
		},
		"CIS-K8S-013": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkRunAsRoot(ctx)
		},
		"CIS-K8S-014": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDangerousCapabilities(ctx)
		},
		"CIS-K8S-015": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkReadOnlyRootFilesystem(ctx)
		},
		"CIS-K8S-016": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkAllowPrivilegeEscalation(ctx)
		},
		"CIS-K8S-017": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkHostPathVolumes(ctx)
		},
		"CIS-K8S-018": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDockerSocketMount(ctx)
		},
		"CIS-K8S-019": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkSeccompProfile(ctx)
		},
		"CIS-K8S-020": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkCPULimits(ctx)
		},
		"CIS-K8S-021": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkMemoryLimits(ctx)
		},
		"CIS-K8S-022": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkResourceRequests(ctx)
		},
		"CIS-K8S-023": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkLivenessProbe(ctx)
		},
		"CIS-K8S-024": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkReadinessProbe(ctx)
		},
		"CIS-K8S-025": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkLatestImageTag(ctx)
		},
		"CIS-K8S-026": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkImagePullPolicy(ctx)
		},
		"CIS-K8S-027": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkHostPort(ctx)
		},
		"CIS-K8S-028": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkAddedCapabilities(ctx)
		},
		// 网络安全
		"CIS-K8S-002": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNetworkPolicy(ctx)
		},
		"CIS-K8S-029": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDefaultDenyIngress(ctx)
		},
		"CIS-K8S-030": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDefaultDenyEgress(ctx)
		},
		"CIS-K8S-031": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodePortServices(ctx)
		},
		"CIS-K8S-032": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkLoadBalancerServices(ctx)
		},
		"CIS-K8S-033": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkExternalIPsServices(ctx)
		},
		"CIS-K8S-034": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkIngressTLS(ctx)
		},
		"CIS-K8S-035": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkServiceWithoutSelector(ctx)
		},
		// 密钥与配置
		"CIS-K8S-036": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkSecretsInEnv(ctx)
		},
		"CIS-K8S-037": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDefaultNamespaceUsage(ctx)
		},
		"CIS-K8S-038": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkTillerDeployment(ctx)
		},
		"CIS-K8S-039": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkLargeSecrets(ctx)
		},
		"CIS-K8S-040": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkLargeConfigMaps(ctx)
		},
		"CIS-K8S-041": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNamespaceLabels(ctx)
		},
		"CIS-K8S-042": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkSATokenSecrets(ctx)
		},
		"CIS-K8S-043": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkPlaintextPasswords(ctx)
		},
		// 工作负载安全
		"CIS-K8S-044": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkSingleReplicaDeployments(ctx)
		},
		"CIS-K8S-045": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkPDBCoverage(ctx)
		},
		"CIS-K8S-046": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkCronJobDeadline(ctx)
		},
		"CIS-K8S-047": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkUntrustedRegistries(ctx)
		},
		"CIS-K8S-048": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkHPAMinReplicas(ctx)
		},
		"CIS-K8S-049": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDaemonSetResourceLimits(ctx)
		},
		"CIS-K8S-050": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkJobBackoffLimit(ctx)
		},
		"CIS-K8S-051": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDeploymentStrategy(ctx)
		},
		"CIS-K8S-052": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkStatefulSetStorage(ctx)
		},
		"CIS-K8S-053": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkPodAntiAffinity(ctx)
		},
		"CIS-K8S-054": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkTopologySpreadConstraints(ctx)
		},
		"CIS-K8S-055": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkDeploymentHPA(ctx)
		},
		// 节点安全
		"CIS-K8S-056": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodeNotReady(ctx)
		},
		"CIS-K8S-057": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodePressure(ctx)
		},
		"CIS-K8S-058": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodeKernelVersion(ctx)
		},
		"CIS-K8S-059": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodeContainerRuntime(ctx)
		},
		"CIS-K8S-060": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodeResourceUtilization(ctx)
		},
		"CIS-K8S-061": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodeUnschedulable(ctx)
		},
		"CIS-K8S-062": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodeTaints(ctx)
		},
		"CIS-K8S-063": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkOrphanPods(ctx)
		},
		"CIS-K8S-064": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNodePodCount(ctx)
		},
		// 集群配置
		"CIS-K8S-065": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkK8sVersion(ctx)
		},
		"CIS-K8S-066": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkLimitRange(ctx)
		},
		"CIS-K8S-067": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkResourceQuota(ctx)
		},
		"CIS-K8S-068": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkPSSLabels(ctx)
		},
		"CIS-K8S-069": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkAdmissionWebhooks(ctx)
		},
		"CIS-K8S-070": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkMutatingWebhookTimeout(ctx)
		},
		"CIS-K8S-071": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkNamespaceCount(ctx)
		},
		"CIS-K8S-072": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkPVReclaimPolicy(ctx)
		},
		"CIS-K8S-073": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkStorageClassExpansion(ctx)
		},
		// 供应链与运行时
		"CIS-K8S-074": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkImageDigest(ctx)
		},
		"CIS-K8S-075": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkInitContainerSecurity(ctx)
		},
		"CIS-K8S-076": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkImagePullSecrets(ctx)
		},
		"CIS-K8S-077": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkPendingPods(ctx)
		},
		"CIS-K8S-078": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkHighRestartPods(ctx)
		},
		"CIS-K8S-079": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkCrashLoopPods(ctx)
		},
		"CIS-K8S-080": func(ctx context.Context, ch *KubeBaselineChecker) (string, model.AffectedResources) {
			return ch.checkPodsWithoutOwner(ctx)
		},
	}
}

// GetRegisteredCheckIDs 获取所有已注册检查函数的 CheckID
func (c *KubeBaselineChecker) GetRegisteredCheckIDs() []string {
	ids := make([]string, 0, len(c.checkFuncs))
	for id := range c.checkFuncs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// RunChecks 对指定集群执行所有基线检查（串行化防止 currentCluster 竞态）
func (c *KubeBaselineChecker) RunChecks(clusterID uint) ([]model.KubeBaseline, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var cluster model.KubeCluster
	if err := c.db.First(&cluster, clusterID).Error; err != nil {
		return nil, fmt.Errorf("集群不存在: %w", err)
	}

	if _, err := c.kubeClient.GetClient(clusterID); err != nil {
		return nil, fmt.Errorf("连接集群失败: %w", err)
	}

	c.currentCluster = clusterID

	// 从数据库读取所有启用的规则
	var rules []model.KubeBaselineRule
	if err := c.db.Where("enabled = ?", true).Order("check_id ASC").Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("读取基线规则失败: %w", err)
	}

	// 先删除该集群旧的检查结果
	c.db.Where("cluster_id = ?", clusterID).Delete(&model.KubeBaseline{})

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	now := model.LocalTime(time.Now())
	var results []model.KubeBaseline

	for _, rule := range rules {
		var result string
		var affected model.AffectedResources

		runFunc, exists := c.checkFuncs[rule.CheckID]
		if exists {
			// 内置规则：用硬编码函数
			result, affected = runFunc(ctx, c)
		} else if rule.CheckConfig != nil && c.ruleEngine != nil {
			// 自定义 CEL 规则：用规则引擎
			clientset := c.getLastClient()
			if clientset == nil {
				result = "error"
			} else {
				result, affected = c.ruleEngine.EvaluateRule(ctx, clientset, rule.CheckConfig)
			}
		} else {
			// 无检查函数也无 CEL 配置，跳过
			continue
		}

		baseline := model.KubeBaseline{
			ClusterID:         clusterID,
			ClusterName:       cluster.Name,
			Category:          rule.Category,
			CheckID:           rule.CheckID,
			CheckName:         rule.CheckName,
			Title:             rule.CheckName,
			Description:       rule.Description,
			Severity:          rule.Severity,
			Result:            result,
			Remediation:       rule.Remediation,
			Benchmark:         rule.Benchmark,
			AffectedResources: affected,
			CheckedAt:         now,
		}

		if err := c.db.Create(&baseline).Error; err != nil {
			c.logger.Error("保存基线检查结果失败", zap.String("check_id", rule.CheckID), zap.Error(err))
			continue
		}
		results = append(results, baseline)
	}

	c.updateHealthScore(clusterID, results)
	c.syncBaselineAlerts(clusterID, cluster.Name, results)
	return results, nil
}

// syncBaselineAlerts ��据检查结果同步基线告警（fail 创建/更新，pass 自动恢复）
func (c *KubeBaselineChecker) syncBaselineAlerts(clusterID uint, clusterName string, results []model.KubeBaseline) {
	now := model.LocalTime(time.Now())

	for _, r := range results {
		fingerprint := model.BaselineAlertFingerprint(clusterID, r.CheckID)

		if r.Result == "fail" {
			var existing model.KubeBaselineAlert
			err := c.db.Where("fingerprint = ?", fingerprint).First(&existing).Error
			if err != nil {
				// 不存在，创建新告警
				alert := model.KubeBaselineAlert{
					ClusterID:         clusterID,
					ClusterName:       clusterName,
					CheckID:           r.CheckID,
					CheckName:         r.CheckName,
					Category:          r.Category,
					Severity:          r.Severity,
					Description:       r.Description,
					Remediation:       r.Remediation,
					AffectedResources: r.AffectedResources,
					Fingerprint:       fingerprint,
					Status:            model.KubeBaselineAlertStatusActive,
					FirstSeenAt:       now,
					LastSeenAt:        now,
				}
				if createErr := c.db.Create(&alert).Error; createErr != nil {
					c.logger.Error("创建基线告警失败", zap.String("check_id", r.CheckID), zap.Error(createErr))
				}
			} else {
				// 已存在，更新 lastSeenAt 和受影响资源；如果之前是 resolved 则重新激活
				updates := map[string]interface{}{
					"last_seen_at":       now,
					"affected_resources": r.AffectedResources,
					"severity":           r.Severity,
					"description":        r.Description,
					"remediation":        r.Remediation,
				}
				if existing.Status == model.KubeBaselineAlertStatusResolved {
					updates["status"] = model.KubeBaselineAlertStatusActive
					updates["resolved_at"] = nil
				}
				c.db.Model(&existing).Updates(updates)
			}
		} else if r.Result == "pass" {
			// 检查通过，自动恢复对应的活跃告警
			c.db.Model(&model.KubeBaselineAlert{}).
				Where("fingerprint = ? AND status = ?", fingerprint, model.KubeBaselineAlertStatusActive).
				Updates(map[string]interface{}{
					"status":      model.KubeBaselineAlertStatusResolved,
					"resolved_at": now,
				})
		}
	}
}

func (c *KubeBaselineChecker) updateHealthScore(clusterID uint, results []model.KubeBaseline) {
	if len(results) == 0 {
		return
	}
	passed := 0
	for _, r := range results {
		if r.Result == "pass" {
			passed++
		}
	}
	score := passed * 100 / len(results)
	c.db.Model(&model.KubeCluster{}).Where("id = ?", clusterID).Update("health_score", score)
}

// getLastClient 获取当前检查集群的客户端
func (c *KubeBaselineChecker) getLastClient() *kubernetes.Clientset {
	clientset, err := c.kubeClient.GetClient(c.currentCluster)
	if err != nil {
		c.logger.Error("获取集群客户端失败", zap.Uint("cluster_id", c.currentCluster), zap.Error(err))
		return nil
	}
	return clientset
}
