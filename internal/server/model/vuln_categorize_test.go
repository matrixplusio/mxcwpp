package model

import "testing"

func TestCategorizeVuln(t *testing.T) {
	cases := []struct {
		name              string
		component         string
		purl              string
		wantCategory      string
		wantRestartAction string
	}{
		// Kernel
		{"rhel kernel", "kernel", "", VulnCategoryKernel, RestartActionRebootHost},
		{"rhel kernel-core", "kernel-core", "", VulnCategoryKernel, RestartActionRebootHost},
		{"rhel kernel-modules", "kernel-modules", "", VulnCategoryKernel, RestartActionRebootHost},
		{"debian linux 短名", "linux", "", VulnCategoryKernel, RestartActionRebootHost},
		{"debian linux-image-6.1", "linux-image-6.1.0-13-amd64", "", VulnCategoryKernel, RestartActionRebootHost},
		{"ubuntu linux-generic", "linux-generic", "", VulnCategoryKernel, RestartActionRebootHost},
		{"linux-firmware", "linux-firmware", "", VulnCategoryKernel, RestartActionRebootHost},
		{"aws optimized kernel", "linux-aws", "", VulnCategoryKernel, RestartActionRebootHost},

		// Critical shared lib
		{"glibc rhel", "glibc", "", VulnCategoryCriticalSharedLib, RestartActionRebootHost},
		{"libc6 debian", "libc6", "", VulnCategoryCriticalSharedLib, RestartActionRebootHost},
		{"libstdc++ rhel", "libstdc++", "", VulnCategoryCriticalSharedLib, RestartActionRebootHost},

		// Shared lib (升级后 restart 依赖服务)
		{"openssl-libs rhel", "openssl-libs", "", VulnCategorySharedLib, RestartActionRestartDependentServices},
		{"libssl3 debian", "libssl3", "", VulnCategorySharedLib, RestartActionRestartDependentServices},
		{"zlib", "zlib", "", VulnCategorySharedLib, RestartActionRestartDependentServices},
		{"libxml2", "libxml2", "", VulnCategorySharedLib, RestartActionRestartDependentServices},
		{"libcurl debian", "libcurl4-openssl-dev", "", VulnCategorySharedLib, RestartActionRestartDependentServices},

		// System daemon
		{"systemd", "systemd", "", VulnCategorySystemDaemon, RestartActionRestartSpecificService},
		{"systemd-udev", "systemd-udev", "", VulnCategorySystemDaemon, RestartActionRestartSpecificService},
		{"openssh-server", "openssh-server", "", VulnCategorySystemDaemon, RestartActionRestartSpecificService},
		{"cron", "cron", "", VulnCategorySystemDaemon, RestartActionRestartSpecificService},
		{"NetworkManager 大小写", "NetworkManager", "", VulnCategorySystemDaemon, RestartActionRestartSpecificService},
		{"polkit", "polkit", "", VulnCategorySystemDaemon, RestartActionRestartSpecificService},

		// CLI tool (无需重启)
		{"sudo", "sudo", "", VulnCategoryCliTool, RestartActionNoAction},
		{"tar", "tar", "", VulnCategoryCliTool, RestartActionNoAction},
		{"openssl CLI", "openssl", "", VulnCategoryCliTool, RestartActionNoAction},
		{"curl", "curl", "", VulnCategoryCliTool, RestartActionNoAction},
		{"git", "git", "", VulnCategoryCliTool, RestartActionNoAction},
		{"vim-enhanced", "vim-enhanced", "", VulnCategoryCliTool, RestartActionNoAction},

		// Web service
		{"nginx", "nginx", "", VulnCategoryWebService, RestartActionRestartSpecificService},
		{"apache2 debian", "apache2", "", VulnCategoryWebService, RestartActionRestartSpecificService},
		{"httpd rhel", "httpd", "", VulnCategoryWebService, RestartActionRestartSpecificService},
		{"php-fpm", "php-fpm", "", VulnCategoryWebService, RestartActionRestartSpecificService},
		{"python3", "python3", "", VulnCategoryWebService, RestartActionRestartSpecificService},
		{"tomcat9", "tomcat9", "", VulnCategoryWebService, RestartActionRestartSpecificService},

		// DB service
		{"mysql-server", "mysql-server", "", VulnCategoryDBService, RestartActionRestartSpecificService},
		{"mariadb-server", "mariadb-server", "", VulnCategoryDBService, RestartActionRestartSpecificService},
		{"postgresql", "postgresql", "", VulnCategoryDBService, RestartActionRestartSpecificService},
		{"redis", "redis", "", VulnCategoryDBService, RestartActionRestartSpecificService},
		{"mongodb-org-server", "mongodb-org-server", "", VulnCategoryDBService, RestartActionRestartSpecificService},

		// Container runtime
		{"docker-ce", "docker-ce", "", VulnCategoryContainerRuntime, RestartActionRestartSpecificService},
		{"containerd.io", "containerd.io", "", VulnCategoryContainerRuntime, RestartActionRestartSpecificService},
		{"runc", "runc", "", VulnCategoryContainerRuntime, RestartActionRestartSpecificService},
		{"kubelet", "kubelet", "", VulnCategoryContainerRuntime, RestartActionRestartSpecificService},

		// Language dep (PURL 决定)
		{"golang pkg", "github.com/foo/bar", "pkg:golang/github.com/foo/bar", VulnCategoryLanguageDep, RestartActionRebuildApp},
		{"npm pkg", "express", "pkg:npm/express", VulnCategoryLanguageDep, RestartActionRebuildApp},
		{"pypi pkg", "flask", "pkg:pypi/flask", VulnCategoryLanguageDep, RestartActionRebuildApp},
		{"maven pkg", "spring", "pkg:maven/org.springframework/spring-core", VulnCategoryLanguageDep, RestartActionRebuildApp},
		{"cargo pkg", "tokio", "pkg:cargo/tokio", VulnCategoryLanguageDep, RestartActionRebuildApp},

		// Edge: component=openssl 但 purl=npm → 应优先归 language_dep
		{"openssl-wrapper npm 优先", "openssl-wrapper", "pkg:npm/openssl-wrapper", VulnCategoryLanguageDep, RestartActionRebuildApp},

		// Other / 兜底
		{"未知包", "weird-pkg-xyz", "", VulnCategoryOther, RestartActionUnknown},
		{"空 component", "", "", VulnCategoryOther, RestartActionUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cat, act := CategorizeVuln(c.component, c.purl)
			if cat != c.wantCategory {
				t.Errorf("category: got %q, want %q", cat, c.wantCategory)
			}
			if act != c.wantRestartAction {
				t.Errorf("action: got %q, want %q", act, c.wantRestartAction)
			}
		})
	}
}
