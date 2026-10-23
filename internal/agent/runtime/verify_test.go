package runtime

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestDetect_InContainerEnvironment 在实际容器环境中验证检测结果
// 此测试只在容器内有意义（当 /.dockerenv 存在时）
func TestDetect_InContainerEnvironment(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("not running in a Docker container, skipping container-specific test")
	}

	log := zap.NewNop()
	info := detect(log)

	// 在 Docker 容器中，应检测为 Docker 类型
	assert.True(t, info.IsContainer, "should detect as container")
	assert.Equal(t, TypeDocker, info.Type, "should detect as Docker type")
	t.Logf("Container detected: type=%s, container_id=%s", info.Type, info.ContainerID)
}

// TestHasSystemd_InContainer 验证容器中 HasSystemd 返回 false
func TestHasSystemd_InContainer(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("not running in a Docker container")
	}

	// 容器中通常没有 systemd
	resetGlobal()
	defer resetGlobal()

	log := zap.NewNop()
	Init(log)

	result := HasSystemd()
	assert.False(t, result, "containers should not have systemd")
}

// TestDetect_VMEnvironment 在主机环境中验证检测结果
func TestDetect_VMEnvironment(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("running in a Docker container, skipping VM-specific test")
	}

	// 确保没有容器相关环境变量
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" || os.Getenv("container") != "" {
		t.Skip("container env vars detected, skipping VM test")
	}

	log := zap.NewNop()
	info := detect(log)

	assert.False(t, info.IsContainer, "should not detect as container on VM/bare metal")
	assert.Equal(t, TypeVM, info.Type, "should detect as VM type")
}

// TestParseCgroupData_CgroupV2_DockerDesktop 验证 Docker Desktop (macOS) 中的 cgroupv2 解析
// Docker Desktop 的容器中 /proc/self/cgroup 通常只包含 "0::/"
func TestParseCgroupData_CgroupV2_DockerDesktop(t *testing.T) {
	// Docker Desktop 的 cgroupv2 没有 docker 路径
	data := "0::/"
	id, typ := parseCgroupData(data)
	assert.Empty(t, id, "cgroupv2 root should not return container ID")
	assert.Empty(t, typ, "cgroupv2 root should not return container type")
}

// TestParseCgroupData_MixedCgroup 验证多行 cgroup 数据中的优先匹配
func TestParseCgroupData_MixedCgroup(t *testing.T) {
	data := strings.Join([]string{
		"12:memory:/user.slice/user-1000.slice",
		"11:cpu:/docker/abc123def456789abcdef",
		"10:blkio:/user.slice",
	}, "\n")

	id, typ := parseCgroupData(data)
	assert.Equal(t, "abc123def456", id)
	assert.Equal(t, "docker", typ)
}
