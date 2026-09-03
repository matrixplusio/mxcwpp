package runtime

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// resetGlobal 重置全局状态以便测试（仅测试使用）
func resetGlobal() {
	mu.Lock()
	defer mu.Unlock()
	globalInfo = nil
	once = sync.Once{}
}

func TestParseCgroupData_Docker(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantID   string
		wantType string
	}{
		{
			name: "cgroupv1 docker",
			data: `12:memory:/docker/abc123def456789abcdef
11:cpu:/docker/abc123def456789abcdef`,
			wantID:   "abc123def456",
			wantType: "docker",
		},
		{
			name: "cgroupv1 docker short id",
			data: `12:memory:/docker/abc123
11:cpu:/system.slice`,
			wantID:   "abc123",
			wantType: "docker",
		},
		{
			name:     "cgroupv2 systemd slice",
			data:     `0::/system.slice/docker-abc123def456789abcdef.scope`,
			wantID:   "abc123def456",
			wantType: "docker",
		},
		{
			name: "containerd",
			data: `12:memory:/containerd/ctr-abc123def456
11:cpu:/containerd/ctr-abc123def456`,
			wantID:   "ctr-abc123def456",
			wantType: "containerd",
		},
		{
			name: "cri-o",
			data: `12:memory:/crio-abc123def456789
11:cpu:/crio-abc123def456789`,
			wantID:   "abc123def456789",
			wantType: "crio",
		},
		{
			name:     "vm no container",
			data:     `12:memory:/user.slice/user-1000.slice/session-1.scope`,
			wantID:   "",
			wantType: "",
		},
		{
			name:     "empty",
			data:     "",
			wantID:   "",
			wantType: "",
		},
		{
			name:     "blank lines",
			data:     "\n\n  \n",
			wantID:   "",
			wantType: "",
		},
		{
			name:     "docker with nested path",
			data:     `12:memory:/docker/abc123def456789/subgroup`,
			wantID:   "abc123def456",
			wantType: "docker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, typ := parseCgroupData(tt.data)
			assert.Equal(t, tt.wantID, id, "container ID mismatch")
			assert.Equal(t, tt.wantType, typ, "container type mismatch")
		})
	}
}

func TestGet_LazyInit(t *testing.T) {
	resetGlobal()
	defer resetGlobal()

	// Get 在 Init 之前调用应自动检测（懒初始化）
	info := Get()
	assert.NotNil(t, info)
	// 结果取决于运行环境
	if _, err := os.Stat("/.dockerenv"); err == nil {
		assert.True(t, info.IsContainer)
	} else {
		assert.Equal(t, TypeVM, info.Type)
	}
}

func TestInit_Idempotent(t *testing.T) {
	resetGlobal()
	defer resetGlobal()

	log := zap.NewNop()

	info1 := Init(log)
	info2 := Init(log) // 第二次调用应返回相同结果（sync.Once）

	assert.Equal(t, info1, info2, "Init should return the same result on repeated calls")
}

func TestGet_AfterInit(t *testing.T) {
	resetGlobal()
	defer resetGlobal()

	log := zap.NewNop()
	Init(log)

	info := Get()
	assert.NotNil(t, info)
	// 结果取决于运行环境
	if _, err := os.Stat("/.dockerenv"); err == nil {
		assert.Equal(t, TypeDocker, info.Type)
		assert.True(t, info.IsContainer)
	} else {
		assert.Equal(t, TypeVM, info.Type)
		assert.False(t, info.IsContainer)
	}
}

func TestIsContainer_AfterInit(t *testing.T) {
	resetGlobal()
	defer resetGlobal()

	log := zap.NewNop()
	Init(log)

	_, dockerenvExists := os.Stat("/.dockerenv")
	if dockerenvExists == nil {
		assert.True(t, IsContainer())
	} else {
		assert.False(t, IsContainer())
	}
}

func TestDetect_K8sEnvVars(t *testing.T) {
	// 模拟 K8s 环境变量
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("HOSTNAME", "my-pod-abc123")
	t.Setenv("POD_NAMESPACE", "default")
	t.Setenv("POD_UID", "uid-123")

	log := zap.NewNop()
	info := detect(log)

	assert.Equal(t, TypeK8s, info.Type)
	assert.True(t, info.IsContainer)
	assert.Equal(t, "my-pod-abc123", info.PodName)
	assert.Equal(t, "default", info.Namespace)
	assert.Equal(t, "uid-123", info.PodUID)
}

func TestDetect_ContainerEnvVar(t *testing.T) {
	// 模拟 container 环境变量（如 systemd-nspawn）
	t.Setenv("container", "systemd-nspawn")

	log := zap.NewNop()
	info := detect(log)

	// 在没有 /.dockerenv 且没有 cgroup 的环境中，仅靠 container 环境变量
	// macOS 上 /proc/self/cgroup 不存在，所以会走到方法4
	assert.Equal(t, TypeDocker, info.Type)
	assert.True(t, info.IsContainer)
}

func TestDetect_VMDefault(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("running in Docker container, skipping VM default test")
	}

	// 确保没有容器相关环境变量
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("container", "")

	log := zap.NewNop()
	info := detect(log)

	assert.Equal(t, TypeVM, info.Type)
	assert.False(t, info.IsContainer)
}

func TestConcurrentAccess(t *testing.T) {
	resetGlobal()
	defer resetGlobal()

	log := zap.NewNop()
	Init(log)

	// 并发读取应该安全
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := Get()
			assert.NotNil(t, info)
			_ = IsContainer()
		}()
	}
	wg.Wait()
}
