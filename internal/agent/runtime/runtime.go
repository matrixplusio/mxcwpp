// Package runtime 提供运行时环境检测功能（容器/VM/K8s）
// 全局单例：检测一次，Agent 全生命周期复用
package runtime

import (
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Type 运行时类型
type Type string

const (
	TypeVM     Type = "vm"     // 虚拟机或物理机
	TypeDocker Type = "docker" // Docker 容器
	TypeK8s    Type = "k8s"    // Kubernetes Pod
)

// Info 运行时环境信息
type Info struct {
	Type        Type   // 运行时类型：vm/docker/k8s
	IsContainer bool   // 是否为容器环境
	ContainerID string // 容器 ID（仅容器环境）
	PodName     string // Pod 名称（仅 K8s）
	PodUID      string // Pod UID（仅 K8s）
	Namespace   string // 命名空间（仅 K8s）
}

var (
	globalInfo *Info
	once       sync.Once
	mu         sync.RWMutex
)

// Init 初始化运行时检测（Agent 启动时调用一次）
func Init(log *zap.Logger) *Info {
	once.Do(func() {
		globalInfo = detect(log)
	})
	return globalInfo
}

// Get 获取运行时信息
// 如果尚未调用 Init，会使用 nop logger 自动检测（保证任何时刻都返回正确结果）
func Get() *Info {
	mu.RLock()
	info := globalInfo
	mu.RUnlock()
	if info != nil {
		return info
	}
	// 未初始化，使用 nop logger 自动初始化
	return Init(zap.NewNop())
}

// IsContainer 快捷方法：是否在容器环境中运行
func IsContainer() bool {
	return Get().IsContainer
}

// HasSystemd 检查是否有 systemd（容器中通常没有）
func HasSystemd() bool {
	if IsContainer() {
		return false
	}
	// 检查 systemd PID 1
	data, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return false
	}
	comm := strings.TrimSpace(string(data))
	return comm == "systemd" || comm == "init"
}

// detect 执行实际的运行时环境检测
func detect(log *zap.Logger) *Info {
	info := &Info{
		Type:        TypeVM,
		IsContainer: false,
	}

	// 方法1：检测 Kubernetes 环境（优先级最高）
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		info.Type = TypeK8s
		info.IsContainer = true
		info.ContainerID = getContainerIDFromCgroup()
		info.PodName = os.Getenv("HOSTNAME")
		info.Namespace = os.Getenv("POD_NAMESPACE")
		if info.Namespace == "" {
			if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
				info.Namespace = strings.TrimSpace(string(data))
			}
		}
		info.PodUID = os.Getenv("POD_UID")
		log.Info("runtime detected: Kubernetes",
			zap.String("pod_name", info.PodName),
			zap.String("namespace", info.Namespace),
			zap.String("container_id", info.ContainerID))
		return info
	}

	// 方法2：检查 /.dockerenv 文件（Docker 容器特有）
	if _, err := os.Stat("/.dockerenv"); err == nil {
		info.Type = TypeDocker
		info.IsContainer = true
		info.ContainerID = getContainerIDFromCgroup()
		log.Info("runtime detected: Docker (/.dockerenv)",
			zap.String("container_id", info.ContainerID))
		return info
	}

	// 方法3：检查 /proc/self/cgroup
	containerID, containerType := getContainerInfoFromCgroup()
	if containerID != "" {
		info.IsContainer = true
		info.ContainerID = containerID
		info.Type = TypeDocker
		log.Info("runtime detected: container (cgroup)",
			zap.String("container_type", containerType),
			zap.String("container_id", containerID))
		return info
	}

	// 方法4：检查 container 环境变量
	if os.Getenv("container") != "" {
		info.Type = TypeDocker
		info.IsContainer = true
		log.Info("runtime detected: container (env var)")
		return info
	}

	log.Info("runtime detected: VM/bare metal")
	return info
}

// getContainerIDFromCgroup 从 cgroup 获取容器 ID
func getContainerIDFromCgroup() string {
	id, _ := getContainerInfoFromCgroup()
	return id
}

// getContainerInfoFromCgroup 从 cgroup 获取容器信息
// 返回 (容器ID, 容器类型)
func getContainerInfoFromCgroup() (string, string) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", ""
	}
	return parseCgroupData(string(data))
}

// parseCgroupData 解析 cgroup 数据，提取容器 ID 和类型
// 独立出来供单元测试使用
func parseCgroupData(data string) (string, string) {
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Docker: "12:memory:/docker/container_id"
		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/docker/")
			if len(parts) > 1 {
				containerID := strings.Split(parts[1], "/")[0]
				if len(containerID) >= 12 {
					return containerID[:12], "docker"
				}
				return containerID, "docker"
			}
		}

		// containerd: "12:memory:/containerd/container_id"
		if strings.Contains(line, "/containerd/") {
			parts := strings.Split(line, "/containerd/")
			if len(parts) > 1 {
				containerID := strings.Split(parts[1], "/")[0]
				return containerID, "containerd"
			}
		}

		// cri-o: "12:memory:/crio-xxxxx"
		if strings.Contains(line, "/crio-") {
			parts := strings.Split(line, "/crio-")
			if len(parts) > 1 {
				containerID := strings.Split(parts[1], "/")[0]
				return containerID, "crio"
			}
		}

		// cgroupv2 的 systemd slice 路径
		// 格式: "0::/system.slice/docker-<id>.scope"
		if strings.Contains(line, "docker-") && strings.HasSuffix(line, ".scope") {
			if _, after, ok := strings.Cut(line, "docker-"); ok {
				containerID := strings.TrimSuffix(after, ".scope")
				if len(containerID) >= 12 {
					return containerID[:12], "docker"
				}
				return containerID, "docker"
			}
		}
	}

	return "", ""
}
