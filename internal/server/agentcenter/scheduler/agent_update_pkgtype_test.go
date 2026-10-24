package scheduler

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Oracle Linux 上报 os_family="ol"，原先拿到的是二进制包而不是 RPM。
func TestDetectPackageType_OracleLinux(t *testing.T) {
	s := &AgentUpdateScheduler{}
	for _, f := range []string{"ol", "oracle", "OracleLinux"} {
		if got := s.detectPackageType(f); got != model.PackageTypeRPM {
			t.Errorf("detectPackageType(%q) = %v, want RPM", f, got)
		}
	}
	if got := s.detectPackageType("ubuntu"); got != model.PackageTypeDEB {
		t.Errorf("detectPackageType(ubuntu) = %v, want DEB", got)
	}
}
