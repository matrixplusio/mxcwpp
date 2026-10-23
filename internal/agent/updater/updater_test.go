package updater

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRestartStrategy_VM 非容器环境应返回 "systemctl"
func TestRestartStrategy_VM(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		t.Skip("running in Docker container")
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" || os.Getenv("container") != "" {
		t.Skip("container env vars set")
	}

	strategy := restartStrategy()
	assert.Equal(t, "systemctl", strategy)
}

// TestRestartStrategy_Container 容器环境应返回 "exit"
func TestRestartStrategy_Container(t *testing.T) {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Skip("not running in Docker container")
	}

	strategy := restartStrategy()
	assert.Equal(t, "exit", strategy)
}

// TestDetectPkgType 不 panic，返回合法值
func TestDetectPkgType(t *testing.T) {
	pkgType := DetectPkgType()
	t.Logf("detected pkg type: %q", pkgType)
	assert.Contains(t, []string{"", "rpm", "deb"}, pkgType)
}
