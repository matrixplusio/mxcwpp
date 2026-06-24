package biz

import (
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

func TestDetectPackageType(t *testing.T) {
	svc := &RemediationService{}

	tests := []struct {
		purl     string
		expected string
	}{
		{"pkg:rpm/redhat/openssl@1.1.1k?arch=x86_64", "rpm"},
		{"pkg:rpm/centos/nginx@1.25.0?arch=aarch64", "rpm"},
		{"pkg:deb/debian/nginx@1.25.0?arch=amd64", "deb"},
		{"pkg:deb/debian/openssh-server@8.2p1~1?arch=amd64", "deb"},
		{"", ""},
		{"pkg:npm/@angular/core@12.0.0", "npm"},
	}

	for _, tt := range tests {
		result := svc.detectPackageType(tt.purl)
		if result != tt.expected {
			t.Errorf("detectPackageType(%q) = %q, want %q", tt.purl, result, tt.expected)
		}
	}
}

func TestGenerateCommands_RPM(t *testing.T) {
	svc := &RemediationService{}

	vuln := &model.Vulnerability{
		Component:    "openssl",
		FixedVersion: "1.1.1k",
		PURL:         "pkg:rpm/redhat/openssl@1.1.0?arch=x86_64",
	}

	commands := svc.generateCommands(vuln)
	if len(commands) != 2 {
		t.Fatalf("expected 2 commands (yum + dnf), got %d", len(commands))
	}

	if commands[0].PackageType != "rpm-yum" {
		t.Errorf("expected package type 'rpm-yum', got %q", commands[0].PackageType)
	}
	// OS pkg 不带 version：vuln DB 的 fixed_version 经常与 OS 实际 erratum 不匹配
	if commands[0].Command != "yum update openssl -y" {
		t.Errorf("unexpected command: %q", commands[0].Command)
	}
	if commands[1].PackageType != "rpm-dnf" {
		t.Errorf("expected package type 'rpm-dnf', got %q", commands[1].PackageType)
	}
	if commands[1].Command != "dnf upgrade openssl -y" {
		t.Errorf("unexpected command: %q", commands[1].Command)
	}
}

func TestGenerateCommands_DEB(t *testing.T) {
	svc := &RemediationService{}

	vuln := &model.Vulnerability{
		Component:    "nginx",
		FixedVersion: "1.25.1",
		PURL:         "pkg:deb/debian/nginx@1.25.0?arch=amd64",
	}

	commands := svc.generateCommands(vuln)
	if len(commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(commands))
	}

	if commands[0].PackageType != "deb" {
		t.Errorf("expected package type 'deb', got %q", commands[0].PackageType)
	}
	if commands[0].Command != "apt-get install --only-upgrade nginx -y" {
		t.Errorf("unexpected command: %q", commands[0].Command)
	}
}

func TestGenerateCommands_UnknownPURL(t *testing.T) {
	svc := &RemediationService{}

	vuln := &model.Vulnerability{
		Component:    "curl",
		FixedVersion: "7.88.0",
		PURL:         "",
	}

	commands := svc.generateCommands(vuln)
	if len(commands) != 3 {
		t.Fatalf("expected 3 commands (rpm-yum + rpm-dnf + deb fallback), got %d", len(commands))
	}
	if commands[0].PackageType != "rpm-yum" {
		t.Errorf("first command should be rpm-yum, got %q", commands[0].PackageType)
	}
	if commands[1].PackageType != "rpm-dnf" {
		t.Errorf("second command should be rpm-dnf, got %q", commands[1].PackageType)
	}
	if commands[2].PackageType != "deb" {
		t.Errorf("third command should be deb, got %q", commands[2].PackageType)
	}
}

func TestGenerateCommands_NoFixedVersion(t *testing.T) {
	svc := &RemediationService{}

	vuln := &model.Vulnerability{
		Component:    "openssl",
		FixedVersion: "",
		PURL:         "pkg:rpm/redhat/openssl@1.1.0?arch=x86_64",
	}

	commands := svc.generateCommands(vuln)
	if len(commands) != 2 {
		t.Fatalf("expected 2 commands (yum + dnf), got %d", len(commands))
	}
	if commands[0].Command != "yum update openssl -y" {
		t.Errorf("unexpected yum command: %q", commands[0].Command)
	}
	if commands[1].Command != "dnf upgrade openssl -y" {
		t.Errorf("unexpected dnf command: %q", commands[1].Command)
	}
}

func TestGetAdvice(t *testing.T) {
	svc := &RemediationService{}

	vuln := &model.Vulnerability{
		ID:           1,
		CveID:        "CVE-2023-1234",
		Component:    "nginx",
		FixedVersion: "1.25.1",
		PURL:         "pkg:rpm/centos/nginx@1.24.0?arch=x86_64",
		ReferenceUrl: "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
	}

	advice := svc.GetAdvice(vuln)

	if advice.VulnID != 1 {
		t.Errorf("expected vulnId=1, got %d", advice.VulnID)
	}
	if advice.CveID != "CVE-2023-1234" {
		t.Errorf("expected cveId=CVE-2023-1234, got %q", advice.CveID)
	}
	if len(advice.Commands) == 0 {
		t.Error("expected at least 1 command")
	}
	if len(advice.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(advice.References))
	}
	if advice.Workaround != "" {
		t.Errorf("expected no workaround when fixedVersion is set, got %q", advice.Workaround)
	}
}

func TestGetAdvice_NoFixedVersion(t *testing.T) {
	svc := &RemediationService{}

	vuln := &model.Vulnerability{
		ID:        2,
		CveID:     "CVE-2023-9999",
		Component: "zlib",
		PURL:      "pkg:rpm/redhat/zlib@1.2.11?arch=x86_64",
	}

	advice := svc.GetAdvice(vuln)

	if advice.Workaround == "" {
		t.Error("expected workaround when no fixedVersion")
	}
}
