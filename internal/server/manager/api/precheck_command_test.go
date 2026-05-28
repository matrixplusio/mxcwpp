package api

import (
	"testing"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

func TestBuildCommandFromPreCheck(t *testing.T) {
	cases := []struct {
		name      string
		hv        model.HostVulnerability
		osFamily  string
		osVersion string
		want      string
	}{
		{
			name: "available rpm-dnf 单包",
			hv: model.HostVulnerability{
				PreCheckStatus:   model.PreCheckStatusAvailable,
				PreCheckPackages: `[{"name":"openssl","installed_version":"1.1.1g","available_version":"1.1.1k","action":"upgrade","repo":"baseos"}]`,
			},
			osFamily: "centos", osVersion: "9",
			want: "dnf upgrade openssl -y",
		},
		{
			name: "available rpm-dnf 多包（openssl + openssl-libs）",
			hv: model.HostVulnerability{
				PreCheckStatus:   model.PreCheckStatusAvailable,
				PreCheckPackages: `[{"name":"openssl","action":"upgrade"},{"name":"openssl-libs","action":"upgrade"}]`,
			},
			osFamily: "rocky", osVersion: "9",
			want: "dnf upgrade openssl openssl-libs -y",
		},
		{
			name: "available_epel 加 --enablerepo=epel",
			hv: model.HostVulnerability{
				PreCheckStatus:   model.PreCheckStatusAvailableEPEL,
				PreCheckPackages: `[{"name":"htop","action":"upgrade"}]`,
			},
			osFamily: "centos", osVersion: "8",
			want: "dnf upgrade --enablerepo=epel htop -y",
		},
		{
			name: "centos 7 用 yum",
			hv: model.HostVulnerability{
				PreCheckStatus:   model.PreCheckStatusAvailable,
				PreCheckPackages: `[{"name":"glibc","action":"upgrade"}]`,
			},
			osFamily: "centos", osVersion: "7",
			want: "yum update glibc -y",
		},
		{
			name: "debian apt",
			hv: model.HostVulnerability{
				PreCheckStatus:   model.PreCheckStatusAvailable,
				PreCheckPackages: `[{"name":"openssl","action":"upgrade"}]`,
			},
			osFamily: "debian", osVersion: "11",
			want: "apt-get install --only-upgrade openssl -y",
		},
		{
			name: "未 precheck → 返回空",
			hv: model.HostVulnerability{
				PreCheckStatus: model.PreCheckStatusUnchecked,
			},
			osFamily: "centos", osVersion: "9",
			want: "",
		},
		{
			name: "not_in_repo → 返回空",
			hv: model.HostVulnerability{
				PreCheckStatus:   model.PreCheckStatusNotInRepo,
				PreCheckPackages: `[{"name":"openssl","action":"not_available"}]`,
			},
			osFamily: "centos", osVersion: "9",
			want: "",
		},
		{
			name: "已最新 action=already_latest → 返回空",
			hv: model.HostVulnerability{
				PreCheckStatus:   model.PreCheckStatusAvailable,
				PreCheckPackages: `[{"name":"openssl","action":"already_latest"}]`,
			},
			osFamily: "centos", osVersion: "9",
			want: "",
		},
		{
			name: "脏 JSON → 返回空",
			hv: model.HostVulnerability{
				PreCheckStatus:   model.PreCheckStatusAvailable,
				PreCheckPackages: "{not json",
			},
			osFamily: "centos", osVersion: "9",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildCommandFromPreCheck(&c.hv, c.osFamily, c.osVersion)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
