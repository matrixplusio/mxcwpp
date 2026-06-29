package main

import "testing"

// 主机级更新命令必须能过 validateCommand 安全白名单。
func TestValidateCommand_HostUpdate(t *testing.T) {
	ok := []string{
		"dnf upgrade --security -y",
		"dnf upgrade -y",
		"yum update --security -y",
		"yum update -y",
	}
	for _, c := range ok {
		if err := validateCommand(c); err != nil {
			t.Errorf("validateCommand(%q) = %v, want nil", c, err)
		}
	}
	// 组合命令(apt 的 &&)会被安全校验拒绝——记录该限制（fleet 当前无 deb 主机）。
	if err := validateCommand("apt-get update && apt-get upgrade -y"); err == nil {
		t.Errorf("validateCommand(apt &&) = nil, want rejected (组合命令)")
	}
}
