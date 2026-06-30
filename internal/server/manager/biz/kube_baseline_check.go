package biz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/kube"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// CheckFunc 基线检查函数签名
type CheckFunc func(ctx context.Context, checker *KubeBaselineChecker) (result string, affected model.AffectedResources)

// KubeBaselineChecker K8s CIS 基线检查器
type KubeBaselineChecker struct {
	db             *gorm.DB
	logger         *zap.Logger
	kubeClient     *KubeClientManager
	ruleEngine     *kube.KubeRuleEngine
	checkFuncs     map[string]CheckFunc
	mu             sync.Mutex // 保护 currentCluster/gkeResults：worker 串行执行单个 task
	currentCluster uint
	notify         chan struct{}     // 入队后唤醒 worker（缓冲 1，非阻塞）
	gkeResults     map[string]string // 当前 task 的 GKE 托管层检查结果（checkID -> pass/fail），run 内有效
}

// NewKubeBaselineChecker 创建基线检查器
func NewKubeBaselineChecker(db *gorm.DB, logger *zap.Logger, kubeClient *KubeClientManager, ruleEngine *kube.KubeRuleEngine) *KubeBaselineChecker {
	c := &KubeBaselineChecker{
		db:         db,
		logger:     logger,
		kubeClient: kubeClient,
		ruleEngine: ruleEngine,
		notify:     make(chan struct{}, 1),
	}
	c.checkFuncs = c.registerCheckFuncs()
	return c
}

// Start 启动后台 worker：先把崩溃残留的 running/pending 任务复位，再循环消费 pending 队列。
// 长任务在后台跑，HTTP 入队即返回，不再阻塞请求 / 超时。
func (c *KubeBaselineChecker) Start(ctx context.Context) {
	// 启动复位：上次进程崩溃时停在 running 的任务标记为 failed（结果不完整，不可信）
	c.db.Model(&model.KubeBaselineTask{}).
		Where("status = ?", model.BaselineTaskRunning).
		Updates(map[string]any{"status": model.BaselineTaskFailed, "error_msg": "进程重启，任务中断"})
	go c.worker(ctx)
	go c.scheduleLoop(ctx)
	// 启动时先排空可能遗留的 pending
	c.signal()
}

// baselineScheduleInterval 定时全量重扫间隔（持续合规：周期性刷新各集群基线，防数据过期）
const baselineScheduleInterval = 24 * time.Hour

// scheduleLoop 周期性为所有集群入队基线检查；跳过已有 pending/running 任务的集群防堆积。
func (c *KubeBaselineChecker) scheduleLoop(ctx context.Context) {
	ticker := time.NewTicker(baselineScheduleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.enqueueAllClusters()
		}
	}
}

// enqueueAllClusters 为每个集群入队一次检查（已有未完成任务的集群跳过）
func (c *KubeBaselineChecker) enqueueAllClusters() {
	var clusters []model.KubeCluster
	if err := c.db.Find(&clusters).Error; err != nil {
		c.logger.Error("定时基线：读取集群列表失败", zap.Error(err))
		return
	}
	for _, cl := range clusters {
		var inflight int64
		c.db.Model(&model.KubeBaselineTask{}).
			Where("cluster_id = ? AND status IN ?", cl.ID,
				[]model.KubeBaselineTaskStatus{model.BaselineTaskPending, model.BaselineTaskRunning}).
			Count(&inflight)
		if inflight > 0 {
			continue
		}
		if _, err := c.EnqueueCheck(cl.ID); err != nil {
			c.logger.Warn("定时基线：入队失败", zap.Uint("cluster_id", cl.ID), zap.Error(err))
		}
	}
}

// signal 非阻塞唤醒 worker
func (c *KubeBaselineChecker) signal() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// worker 后台循环：被 notify 唤醒或定时兜底，排空 pending 队列
func (c *KubeBaselineChecker) worker(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.notify:
		case <-ticker.C:
		}
		c.drainPending(ctx)
	}
}

// drainPending 逐个取出最早的 pending 任务执行，直到队列空
func (c *KubeBaselineChecker) drainPending(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		var task model.KubeBaselineTask
		err := c.db.Where("status = ?", model.BaselineTaskPending).
			Order("id ASC").First(&task).Error
		if err != nil {
			return // 没有 pending（含 ErrRecordNotFound）
		}
		c.runTask(ctx, task)
	}
}

// EnqueueCheck 入队一次基线检查，立即返回 task_id（异步执行）
func (c *KubeBaselineChecker) EnqueueCheck(clusterID uint) (uint, error) {
	var cluster model.KubeCluster
	if err := c.db.First(&cluster, clusterID).Error; err != nil {
		return 0, fmt.Errorf("集群不存在: %w", err)
	}
	task := model.KubeBaselineTask{
		ClusterID:   clusterID,
		ClusterName: cluster.Name,
		Status:      model.BaselineTaskPending,
		StartedAt:   model.LocalTime(time.Now()),
	}
	if err := c.db.Create(&task).Error; err != nil {
		return 0, fmt.Errorf("创建基线任务失败: %w", err)
	}
	c.signal()
	return task.ID, nil
}

// evalGKE 拉取并评估 GKE 托管层配置（Container API）；无 GCP 坐标或拉取失败时返回 nil，
// 对应 CIS-GKE-* 检查记为 error（需为集群配置 GCP project/location + 具 container.clusters.get 的 SA）。
func (c *KubeBaselineChecker) evalGKE(ctx context.Context, cluster model.KubeCluster) map[string]string {
	if cluster.GCPProjectID == "" || cluster.GCPLocation == "" {
		c.logger.Info("跳过 GKE 托管层检查：未配置 GCP 坐标", zap.Uint("cluster_id", cluster.ID))
		return nil
	}
	name := cluster.GCPClusterName
	if name == "" {
		name = cluster.Name
	}
	cfg, err := kube.FetchGKECluster(ctx, cluster.GCPProjectID, cluster.GCPLocation, name, cluster.GCPCredentialsJSON)
	if err != nil {
		c.logger.Warn("拉取 GKE 集群配置失败，托管层检查记为 error",
			zap.Uint("cluster_id", cluster.ID), zap.Error(err))
		return nil
	}
	return kube.EvaluateGKEChecks(cfg)
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

// runTask 执行单个 pending 基线任务：claim(pending->running) -> 跑规则 -> 完成/失败。
// 串行化(mu)防 currentCluster 竞态；由后台 worker 调用，不阻塞 HTTP。
func (c *KubeBaselineChecker) runTask(parent context.Context, task model.KubeBaselineTask) {
	c.mu.Lock()
	defer c.mu.Unlock()

	clusterID := task.ClusterID

	// claim：pending -> running（CAS，防重复执行）
	claim := c.db.Model(&model.KubeBaselineTask{}).
		Where("id = ? AND status = ?", task.ID, model.BaselineTaskPending).
		Updates(map[string]any{"status": model.BaselineTaskRunning, "started_at": model.LocalTime(time.Now())})
	if claim.Error != nil || claim.RowsAffected == 0 {
		return // 已被其它流程处理/取消
	}

	failTask := func(msg string, err error) {
		c.logger.Error("基线任务失败", zap.Uint("task_id", task.ID), zap.String("reason", msg), zap.Error(err))
		c.db.Model(&model.KubeBaselineTask{}).Where("id = ?", task.ID).Updates(map[string]any{
			"status":      model.BaselineTaskFailed,
			"error_msg":   msg,
			"finished_at": model.LocalTime(time.Now()),
		})
	}

	var cluster model.KubeCluster
	if err := c.db.First(&cluster, clusterID).Error; err != nil {
		failTask("集群不存在", err)
		return
	}
	if _, err := c.kubeClient.GetClient(clusterID); err != nil {
		failTask("连接集群失败", err)
		return
	}

	c.currentCluster = clusterID

	// 从数据库读取所有启用的规则
	var rules []model.KubeBaselineRule
	if err := c.db.Where("enabled = ?", true).Order("check_id ASC").Find(&rules).Error; err != nil {
		failTask("读取基线规则失败", err)
		return
	}

	// 清理 refactor 前遗留的无任务结果行
	c.db.Where("cluster_id = ? AND (task_id IS NULL OR task_id = 0)", clusterID).Delete(&model.KubeBaseline{})

	ctx, cancel := context.WithTimeout(parent, 180*time.Second)
	defer cancel()

	// GKE 托管层检查：一次拉取集群 GCP 配置，结果在本 run 内复用
	c.gkeResults = c.evalGKE(ctx, cluster)

	now := model.LocalTime(time.Now())
	var results []model.KubeBaseline

	for _, rule := range rules {
		var result string
		var affected model.AffectedResources

		runFunc, exists := c.checkFuncs[rule.CheckID]
		if strings.HasPrefix(rule.CheckID, "CIS-GKE-") {
			// GKE 托管层规则：读 GCP Container API 评估结果；配置不可用记为 error
			if r, ok := c.gkeResults[rule.CheckID]; ok {
				result = r
			} else {
				result = "error"
			}
		} else if exists {
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
			TaskID:            task.ID,
			Category:          rule.Category,
			CheckID:           rule.CheckID,
			CheckName:         rule.CheckName,
			Title:             rule.CheckName,
			Description:       rule.Description,
			Severity:          rule.Severity,
			Result:            result,
			Remediation:       rule.Remediation,
			Benchmark:         rule.Benchmark,
			ControlRef:        rule.ControlRef,
			AffectedResources: affected,
			CheckedAt:         now,
		}

		if err := c.db.Create(&baseline).Error; err != nil {
			c.logger.Error("保存基线检查结果失败", zap.String("check_id", rule.CheckID), zap.Error(err))
			continue
		}
		results = append(results, baseline)
	}

	// 统计并完成任务
	passed, failed, errCnt := 0, 0, 0
	for _, r := range results {
		switch r.Result {
		case "pass":
			passed++
		case "fail":
			failed++
		default:
			errCnt++
		}
	}
	rate := 0.0
	if len(results) > 0 {
		rate = float64(passed) / float64(len(results)) * 100
	}
	weighted := weightedComplianceScore(results)
	fin := model.LocalTime(time.Now())
	c.db.Model(&task).Updates(map[string]any{
		"status":         model.BaselineTaskDone,
		"total":          len(results),
		"passed":         passed,
		"failed":         failed,
		"error_cnt":      errCnt,
		"pass_rate":      rate,
		"weighted_score": weighted,
		"finished_at":    fin,
	})
	c.pruneOldTasks(clusterID, 10)

	// 集群健康分用加权合规分（critical 失败惩罚更重，比扁平通过率更贴近风险）
	c.db.Model(&model.KubeCluster{}).Where("id = ?", clusterID).Update("health_score", weighted)
	c.syncBaselineAlerts(clusterID, cluster.Name, results)
}

// severityWeight 严重度权重：critical 失败对合规分影响远大于 low
func severityWeight(severity string) int {
	switch severity {
	case "critical":
		return 10
	case "high":
		return 5
	case "medium":
		return 2
	default: // low / 其它
		return 1
	}
}

// weightedComplianceScore 严重度加权合规分(0-100)：通过项权重和 / 全部项权重和。
// error 项按其严重度计入分母但不计入分子（视为未通过），避免拉取失败被当作合规。
func weightedComplianceScore(results []model.KubeBaseline) int {
	totalW, passW := 0, 0
	for _, r := range results {
		w := severityWeight(r.Severity)
		totalW += w
		if r.Result == "pass" {
			passW += w
		}
	}
	if totalW == 0 {
		return 100
	}
	return passW * 100 / totalW
}

// pruneOldTasks 仅保留每集群最近 keep 个任务，删除更早的任务及其结果行
func (c *KubeBaselineChecker) pruneOldTasks(clusterID uint, keep int) {
	var ids []uint
	c.db.Model(&model.KubeBaselineTask{}).
		Where("cluster_id = ?", clusterID).
		Order("id DESC").Offset(keep).Pluck("id", &ids)
	if len(ids) == 0 {
		return
	}
	c.db.Where("task_id IN ?", ids).Delete(&model.KubeBaseline{})
	c.db.Where("id IN ?", ids).Delete(&model.KubeBaselineTask{})
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

// getLastClient 获取当前检查集群的客户端
func (c *KubeBaselineChecker) getLastClient() *kubernetes.Clientset {
	clientset, err := c.kubeClient.GetClient(c.currentCluster)
	if err != nil {
		c.logger.Error("获取集群客户端失败", zap.Uint("cluster_id", c.currentCluster), zap.Error(err))
		return nil
	}
	return clientset
}
