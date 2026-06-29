package api

import "testing"

func TestBuildHostUpdateCommand(t *testing.T) {
	cases := []struct {
		osFamily, osVer, scope string
		wantCmd                string
	}{
		// RHEL8+/Rocky/CentOS9 → dnf
		{"rocky", "9.4", "security", "dnf upgrade --security -y"},
		{"rocky", "9.4", "all", "dnf upgrade -y"},
		{"centos", "9", "security", "dnf upgrade --security -y"},
		{"rhel", "8.9", "security", "dnf upgrade --security -y"},
		{"oracle", "9", "all", "dnf upgrade -y"},
		// CentOS7/RHEL7 → yum
		{"centos", "7.9", "security", "yum update --security -y"},
		{"centos", "7", "all", "yum update -y"},
		// deb
		{"ubuntu", "22.04", "security", "apt-get upgrade -y"},
		{"debian", "12", "all", "apt-get dist-upgrade -y"},
	}
	for _, c := range cases {
		gotCmd, gotLabel := buildHostUpdateCommand(c.osFamily, c.osVer, c.scope)
		if gotCmd != c.wantCmd {
			t.Errorf("%s/%s/%s: cmd=%q want %q", c.osFamily, c.osVer, c.scope, gotCmd, c.wantCmd)
		}
		if gotLabel == "" {
			t.Errorf("%s/%s/%s: empty label", c.osFamily, c.osVer, c.scope)
		}
	}
}
