package model

import "testing"

func TestDeriveAssetType(t *testing.T) {
	cases := []struct {
		name          string
		scope         string
		sourceHandler string
		want          string
	}{
		// scope=embedded → 永远 app
		{"embedded go", "embedded", "go_buildinfo", AssetTypeApp},
		{"embedded jar", "embedded", "jar_scanner", AssetTypeApp},
		{"embedded binary", "embedded", "binary_probe", AssetTypeApp},

		// scope=container → 永远 container
		{"container sbom", "container", "container_sbom", AssetTypeContainer},
		{"container empty handler", "container", "", AssetTypeContainer},

		// scope=system + OS 包管理 → os
		{"system rpm", "system", "rpm", AssetTypeOS},
		{"system dpkg", "system", "dpkg", AssetTypeOS},
		{"system apk", "system", "apk", AssetTypeOS},

		// scope=system + 中间件类 handler → middleware
		{"system jar", "system", "jar_scanner", AssetTypeMiddleware},
		{"system binary_probe", "system", "binary_probe", AssetTypeMiddleware},
		{"system go_buildinfo on host", "system", "go_buildinfo", AssetTypeMiddleware},
		{"system python", "system", "python", AssetTypeMiddleware},

		// scope 空 + handler 空 → unknown
		{"both empty", "", "", AssetTypeUnknown},
		// scope=system + 未识别 handler → 兜底 OS
		{"system unknown handler", "system", "weirdo", AssetTypeOS},

		// 大小写 / 空格
		{"upper scope", "EMBEDDED", "GO_BUILDINFO", AssetTypeApp},
		{"trim", "  system  ", "  rpm  ", AssetTypeOS},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DeriveAssetType(c.scope, c.sourceHandler)
			if got != c.want {
				t.Errorf("DeriveAssetType(%q,%q) = %q, want %q",
					c.scope, c.sourceHandler, got, c.want)
			}
		})
	}
}

func TestDeriveFixOwner(t *testing.T) {
	cases := []struct {
		name         string
		assetType    string
		vulnCategory string
		subscope     string
		want         string
	}{
		// subscope 优先(无视 assetType)
		{"cloud_agent → cloud_provider", AssetTypeApp, VulnCategoryLanguageDep, SubscopeCloudAgent, FixOwnerCloudProvider},
		{"monitoring → apm_vendor", AssetTypeMiddleware, VulnCategoryLanguageDep, SubscopeMonitoringAgent, FixOwnerAPMVendor},
		{"security_agent → platform_team", AssetTypeApp, VulnCategoryOther, SubscopeSecurityAgent, FixOwnerPlatformTeam},

		// app → dev
		{"app any → dev", AssetTypeApp, VulnCategoryLanguageDep, SubscopeBusinessBinary, FixOwnerDev},
		{"app kernel → dev (asset wins)", AssetTypeApp, VulnCategoryKernel, SubscopeBusinessBinary, FixOwnerDev},

		// container/image → image_maintainer
		{"container → image_maintainer", AssetTypeContainer, VulnCategoryLanguageDep, SubscopeUnknown, FixOwnerImageMaintainer},
		{"image → image_maintainer", AssetTypeImage, VulnCategoryKernel, SubscopeUnknown, FixOwnerImageMaintainer},

		// OS + vuln_category 决定细分
		{"os db_service → dba", AssetTypeOS, VulnCategoryDBService, SubscopeOSPackage, FixOwnerDBA},
		{"os web_service → sre", AssetTypeOS, VulnCategoryWebService, SubscopeOSPackage, FixOwnerSRE},
		{"os container_runtime → sre", AssetTypeOS, VulnCategoryContainerRuntime, SubscopeOSPackage, FixOwnerSRE},
		{"os virtualization → sre", AssetTypeOS, VulnCategoryVirtualization, SubscopeOSPackage, FixOwnerSRE},
		{"os kernel → ops", AssetTypeOS, VulnCategoryKernel, SubscopeOSPackage, FixOwnerOps},
		{"os shared_lib → ops", AssetTypeOS, VulnCategorySharedLib, SubscopeSystemLib, FixOwnerOps},
		{"os cli → ops", AssetTypeOS, VulnCategoryCliTool, SubscopeOSPackage, FixOwnerOps},

		// middleware
		{"middleware db → dba", AssetTypeMiddleware, VulnCategoryDBService, SubscopeOSPackage, FixOwnerDBA},
		{"middleware web → sre", AssetTypeMiddleware, VulnCategoryWebService, SubscopeOSPackage, FixOwnerSRE},
		{"middleware language_dep → dev", AssetTypeMiddleware, VulnCategoryLanguageDep, SubscopeBusinessJar, FixOwnerDev},
		{"middleware other → sre", AssetTypeMiddleware, VulnCategoryOther, SubscopeBusinessJar, FixOwnerSRE},

		// unknown
		{"unknown → unknown", AssetTypeUnknown, VulnCategoryOther, SubscopeUnknown, FixOwnerUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DeriveFixOwner(c.assetType, c.vulnCategory, c.subscope)
			if got != c.want {
				t.Errorf("DeriveFixOwner(%q,%q,%q) = %q, want %q",
					c.assetType, c.vulnCategory, c.subscope, got, c.want)
			}
		})
	}
}

func TestDeriveSubscope(t *testing.T) {
	cases := []struct {
		name       string
		binaryPath string
		scope      string
		handler    string
		comp       string
		want       string
	}{
		// 云厂商 agent
		{"gcp osconfig", "/usr/bin/google_osconfig_agent", "embedded", "go_buildinfo", "golang.org/x/crypto", SubscopeCloudAgent},
		{"gcp guest agent", "/usr/bin/google_guest_agent", "embedded", "go_buildinfo", "github.com/docker/docker", SubscopeCloudAgent},
		{"aws ssm", "/usr/bin/amazon-ssm-agent", "embedded", "go_buildinfo", "x", SubscopeCloudAgent},
		{"azure waagent", "/usr/sbin/waagent", "embedded", "binary_probe", "x", SubscopeCloudAgent},

		// 监控探针
		{"skywalking jar", "/opt/skywalking-agent/plugins/foo.jar", "system", "jar_scanner", "io.netty:netty-codec", SubscopeMonitoringAgent},
		{"datadog", "/opt/datadog-agent/bin/agent", "embedded", "go_buildinfo", "x", SubscopeMonitoringAgent},
		{"node_exporter", "/usr/local/bin/node_exporter", "embedded", "go_buildinfo", "x", SubscopeMonitoringAgent},

		// 安全 agent (mxcwpp 自身)
		{"mxcwpp-agent self", "/usr/bin/mxcwpp-agent", "embedded", "go_buildinfo", "golang.org/x/crypto", SubscopeSecurityAgent},

		// 真业务 binary (路径不匹配系统)
		{"business go", "/opt/app/myservice", "embedded", "go_buildinfo", "x", SubscopeBusinessBinary},
		{"business jar", "/opt/app/lib/biz.jar", "system", "jar_scanner", "io.netty:netty-codec", SubscopeBusinessJar},

		// OS 包
		{"rpm pkg", "", "system", "rpm", "kernel", SubscopeOSPackage},
		{"dpkg pkg", "", "system", "dpkg", "libssl3", SubscopeSystemLib}, // shared_lib 优先
		{"empty handler system → os", "", "system", "", "kernel", SubscopeOSPackage},

		// 系统库
		{"glibc", "", "system", "rpm", "glibc", SubscopeSystemLib},
		{"libssl", "", "system", "rpm", "openssl-libs", SubscopeSystemLib},

		// unknown
		{"all empty", "", "", "", "", SubscopeOSPackage}, // 兜底 OS
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DeriveSubscope(c.binaryPath, c.scope, c.handler, c.comp)
			if got != c.want {
				t.Errorf("DeriveSubscope(%q,%q,%q,%q) = %q, want %q",
					c.binaryPath, c.scope, c.handler, c.comp, got, c.want)
			}
		})
	}
}
