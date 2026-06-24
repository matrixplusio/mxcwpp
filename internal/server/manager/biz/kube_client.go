package biz

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// KubeClientManager 管理 K8s 集群客户端连接池
type KubeClientManager struct {
	db      *gorm.DB
	logger  *zap.Logger
	clients map[uint]*kubeClientEntry
	mu      sync.RWMutex
}

type kubeClientEntry struct {
	clientset *kubernetes.Clientset
	createdAt time.Time
}

// NewKubeClientManager 创建 KubeClientManager
func NewKubeClientManager(db *gorm.DB, logger *zap.Logger) *KubeClientManager {
	return &KubeClientManager{
		db:      db,
		logger:  logger,
		clients: make(map[uint]*kubeClientEntry),
	}
}

// Connect 使用 KubeConfig 创建客户端连接并验证连通性
func (m *KubeClientManager) Connect(kubeConfig string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeConfig))
	if err != nil {
		return nil, fmt.Errorf("解析 KubeConfig 失败: %w", err)
	}
	config.Timeout = 10 * time.Second

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("创建 K8s 客户端失败: %w", err)
	}

	// 验证连通性
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("连接 K8s 集群失败: %w", err)
	}
	_ = ctx

	return clientset, nil
}

// GetClient 获取指定集群的客户端，自动创建或重用缓存
func (m *KubeClientManager) GetClient(clusterID uint) (*kubernetes.Clientset, error) {
	m.mu.RLock()
	entry, ok := m.clients[clusterID]
	m.mu.RUnlock()

	// 缓存有效期 5 分钟
	if ok && time.Since(entry.createdAt) < 5*time.Minute {
		return entry.clientset, nil
	}

	// 从数据库读取 KubeConfig
	var cluster model.KubeCluster
	if err := m.db.First(&cluster, clusterID).Error; err != nil {
		return nil, fmt.Errorf("集群不存在: %w", err)
	}

	clientset, err := m.Connect(cluster.KubeConfig)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.clients[clusterID] = &kubeClientEntry{
		clientset: clientset,
		createdAt: time.Now(),
	}
	m.mu.Unlock()

	return clientset, nil
}

// GetRESTConfig 读取集群 KubeConfig 并返回 rest.Config（供 dynamic / discovery 客户端使用）
func (m *KubeClientManager) GetRESTConfig(clusterID uint) (*rest.Config, error) {
	var cluster model.KubeCluster
	if err := m.db.First(&cluster, clusterID).Error; err != nil {
		return nil, fmt.Errorf("集群不存在: %w", err)
	}
	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(cluster.KubeConfig))
	if err != nil {
		return nil, fmt.Errorf("解析 KubeConfig 失败: %w", err)
	}
	config.Timeout = 30 * time.Second
	return config, nil
}

// RemoveClient 移除指定集群的客户端缓存
func (m *KubeClientManager) RemoveClient(clusterID uint) {
	m.mu.Lock()
	delete(m.clients, clusterID)
	m.mu.Unlock()
}

// NodeInfo K8s 节点信息（前端展示格式）
type NodeInfo struct {
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	Roles          string  `json:"roles"`
	IP             string  `json:"ip"`
	OS             string  `json:"os"`
	CPUPercent     float64 `json:"cpuPercent"`
	MemoryPercent  float64 `json:"memoryPercent"`
	PodCount       int     `json:"podCount"`
	KubeletVersion string  `json:"kubeletVersion"`
}

// PodInfo K8s Pod 信息（前端展示格式）
type PodInfo struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	Status          string `json:"status"`
	ReadyContainers int    `json:"readyContainers"`
	TotalContainers int    `json:"totalContainers"`
	Restarts        int32  `json:"restarts"`
	NodeName        string `json:"nodeName"`
	PodIP           string `json:"podIp"`
	Age             string `json:"age"`
}

// WorkloadInfo K8s Workload 信息（前端展示格式）
type WorkloadInfo struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Namespace       string `json:"namespace"`
	ReadyReplicas   int32  `json:"readyReplicas"`
	DesiredReplicas int32  `json:"desiredReplicas"`
	Images          string `json:"images"`
	CreatedAt       string `json:"createdAt"`
}

// GetNodes 获取集群节点列表
func (m *KubeClientManager) GetNodes(clusterID uint) ([]NodeInfo, error) {
	clientset, err := m.GetClient(clusterID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("查询节点列表失败: %w", err)
	}

	// 获取所有 Pod 以计算每节点 Pod 数
	pods, _ := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	nodePodCount := make(map[string]int)
	if pods != nil {
		for _, pod := range pods.Items {
			nodePodCount[pod.Spec.NodeName]++
		}
	}

	result := make([]NodeInfo, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		info := NodeInfo{
			Name:           node.Name,
			Status:         getNodeStatus(node),
			Roles:          getNodeRoles(node),
			IP:             getNodeIP(node),
			OS:             node.Status.NodeInfo.OSImage,
			PodCount:       nodePodCount[node.Name],
			KubeletVersion: node.Status.NodeInfo.KubeletVersion,
		}

		// 计算资源使用率（基于 Allocatable vs Capacity）
		if cpu := node.Status.Allocatable.Cpu(); cpu != nil {
			if capCPU := node.Status.Capacity.Cpu(); capCPU != nil && capCPU.MilliValue() > 0 {
				used := capCPU.MilliValue() - cpu.MilliValue()
				info.CPUPercent = float64(used) / float64(capCPU.MilliValue()) * 100
			}
		}
		if mem := node.Status.Allocatable.Memory(); mem != nil {
			if capMem := node.Status.Capacity.Memory(); capMem != nil && capMem.Value() > 0 {
				used := capMem.Value() - mem.Value()
				info.MemoryPercent = float64(used) / float64(capMem.Value()) * 100
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// GetPods 获取 Pod 列表（支持分页和过滤）
func (m *KubeClientManager) GetPods(clusterID uint, namespace, search, status string, page, pageSize int) ([]PodInfo, int, error) {
	clientset, err := m.GetClient(clusterID)
	if err != nil {
		return nil, 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ns := ""
	if namespace != "" {
		ns = namespace
	}

	pods, err := clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, 0, fmt.Errorf("查询 Pod 列表失败: %w", err)
	}

	// 过滤
	var filtered []corev1.Pod
	for _, pod := range pods.Items {
		if search != "" && !strings.Contains(pod.Name, search) {
			continue
		}
		if status != "" && string(pod.Status.Phase) != status {
			continue
		}
		filtered = append(filtered, pod)
	}

	total := len(filtered)

	// 分页
	start := (page - 1) * pageSize
	if start >= total {
		return []PodInfo{}, total, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	paged := filtered[start:end]

	result := make([]PodInfo, 0, len(paged))
	for _, pod := range paged {
		ready := 0
		var restarts int32
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Ready {
				ready++
			}
			restarts += cs.RestartCount
		}

		result = append(result, PodInfo{
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			Status:          string(pod.Status.Phase),
			ReadyContainers: ready,
			TotalContainers: len(pod.Spec.Containers),
			Restarts:        restarts,
			NodeName:        pod.Spec.NodeName,
			PodIP:           pod.Status.PodIP,
			Age:             formatAge(pod.CreationTimestamp.Time),
		})
	}

	return result, total, nil
}

// GetWorkloads 获取 Workload 列表（Deployments + StatefulSets + DaemonSets）
func (m *KubeClientManager) GetWorkloads(clusterID uint) ([]WorkloadInfo, error) {
	clientset, err := m.GetClient(clusterID)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var result []WorkloadInfo

	// Deployments
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, d := range deployments.Items {
			result = append(result, WorkloadInfo{
				Name:            d.Name,
				Type:            "Deployment",
				Namespace:       d.Namespace,
				ReadyReplicas:   d.Status.ReadyReplicas,
				DesiredReplicas: ptrInt32(d.Spec.Replicas),
				Images:          getWorkloadImages(d.Spec.Template.Spec.Containers),
				CreatedAt:       d.CreationTimestamp.Format("2006-01-02 15:04:05"),
			})
		}
	}

	// StatefulSets
	statefulSets, err := clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, s := range statefulSets.Items {
			result = append(result, WorkloadInfo{
				Name:            s.Name,
				Type:            "StatefulSet",
				Namespace:       s.Namespace,
				ReadyReplicas:   s.Status.ReadyReplicas,
				DesiredReplicas: ptrInt32(s.Spec.Replicas),
				Images:          getWorkloadImages(s.Spec.Template.Spec.Containers),
				CreatedAt:       s.CreationTimestamp.Format("2006-01-02 15:04:05"),
			})
		}
	}

	// DaemonSets
	daemonSets, err := clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, d := range daemonSets.Items {
			result = append(result, WorkloadInfo{
				Name:            d.Name,
				Type:            "DaemonSet",
				Namespace:       d.Namespace,
				ReadyReplicas:   d.Status.NumberReady,
				DesiredReplicas: d.Status.DesiredNumberScheduled,
				Images:          getWorkloadImages(d.Spec.Template.Spec.Containers),
				CreatedAt:       d.CreationTimestamp.Format("2006-01-02 15:04:05"),
			})
		}
	}

	return result, nil
}

// GetClusterInfo 获取集群概览信息
func (m *KubeClientManager) GetClusterInfo(clusterID uint) (version string, nodeCount, podCount, namespaceCount, deploymentCount, serviceCount int, namespaces []string, err error) {
	clientset, cErr := m.GetClient(clusterID)
	if cErr != nil {
		err = cErr
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 版本
	sv, vErr := clientset.Discovery().ServerVersion()
	if vErr == nil {
		version = sv.GitVersion
	}

	// 节点
	nodes, _ := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if nodes != nil {
		nodeCount = len(nodes.Items)
	}

	// Pod
	pods, _ := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if pods != nil {
		podCount = len(pods.Items)
	}

	// Namespace
	nsList, _ := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if nsList != nil {
		namespaceCount = len(nsList.Items)
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	}

	// Deployments
	deployments, _ := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if deployments != nil {
		deploymentCount = len(deployments.Items)
	}

	// Services
	services, _ := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if services != nil {
		serviceCount = len(services.Items)
	}

	return
}

// 辅助函数

func getNodeStatus(node corev1.Node) string {
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			if cond.Status == corev1.ConditionTrue {
				return "Ready"
			}
			return "NotReady"
		}
	}
	return "Unknown"
}

func getNodeRoles(node corev1.Node) string {
	var roles []string
	for label := range node.Labels {
		if strings.HasPrefix(label, "node-role.kubernetes.io/") {
			role := strings.TrimPrefix(label, "node-role.kubernetes.io/")
			if role != "" {
				roles = append(roles, role)
			}
		}
	}
	if len(roles) == 0 {
		return "<none>"
	}
	return strings.Join(roles, ",")
}

func getNodeIP(node corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	return ""
}

func getWorkloadImages(containers []corev1.Container) string {
	var images []string
	for _, c := range containers {
		images = append(images, c.Image)
	}
	return strings.Join(images, ", ")
}

func ptrInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	if d.Hours() >= 24*30 {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if d.Hours() >= 24 {
		return fmt.Sprintf("%dd%dh", int(d.Hours()/24), int(d.Hours())%24)
	}
	if d.Hours() >= 1 {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
