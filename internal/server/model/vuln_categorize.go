// Package biz — 漏洞分类 + 重启影响推导（P5）。
//
// 9 类 vuln_category × 5 动作 restart_action，UI 修复弹窗按动作分级警示，
// 让运维提前知道"修了要 reboot 主机"vs"重启某服务"vs"无需重启"。
//
// 设计深度评估见 docs/p5-vuln-categorize.md / project_cwpp_remediation_design memory。
//
// 关键洞察：
//   - openssl 包本身升级不需要重启，但所有 link libssl 的服务（nginx/sshd/postgres/...）
//     必须重启才能加载新代码 → 归 shared_lib + restart_dependent_services
//   - glibc/libc6 升级影响几乎所有进程，实际等同 reboot → critical_shared_lib + reboot_host
//   - kernel 升级新内核装到 /boot，运行中的内核还是老的 → 必须 reboot（除非 livepatch）
//   - CLI 工具（sudo/tar/rpm）下次调用自动用新版 → no_action
package model

import "strings"

// VulnCategory 9 类枚举（写入 vulnerabilities.vuln_category）
const (
	VulnCategoryKernel            = "kernel"
	VulnCategoryCriticalSharedLib = "critical_shared_lib" // glibc/libc6/musl — 实际等同 reboot
	VulnCategorySharedLib         = "shared_lib"          // openssl/zlib/libxml2 — 升级后需 restart 依赖服务
	VulnCategorySystemDaemon      = "system_daemon"       // systemd/sshd/cron/NetworkManager
	VulnCategoryCliTool           = "cli_tool"            // sudo/tar/rpm/curl — 无需重启
	VulnCategoryWebService        = "web_service"         // nginx/apache/php-fpm/python/java
	VulnCategoryDBService         = "db_service"          // mysql/postgres/redis/mongodb — 重启 = DB 中断
	VulnCategoryContainerRuntime  = "container_runtime"   // docker/containerd/runc/kubelet
	VulnCategoryLanguageDep       = "language_dep"        // pkg:golang/npm/pypi/maven — 平台范围外
	VulnCategoryOther             = "other"
)

// RestartAction 5 动作枚举（写入 vulnerabilities.restart_action）
const (
	RestartActionRebootHost               = "reboot_host"
	RestartActionRestartDependentServices = "restart_dependent_services" // shared_lib → P5.2 agent lsof 找
	RestartActionRestartSpecificService   = "restart_specific_service"
	RestartActionNoAction                 = "no_action"
	RestartActionRebuildApp               = "rebuild_app"
	RestartActionUnknown                  = "unknown"
)

// CategorizeVuln 根据 component + purl 推导分类 + 重启动作。
// 优先级（高→低）：language_dep（PURL 优先） > kernel > critical_shared_lib >
//
//	container_runtime > system_daemon > cli_tool > web_service >
//	db_service > shared_lib > other
func CategorizeVuln(component, purl string) (category, action string) {
	comp := strings.ToLower(strings.TrimSpace(component))
	purlLower := strings.ToLower(strings.TrimSpace(purl))

	// 1. 语言层依赖（PURL 优先匹配，避免 component=openssl 被 npm 包 openssl-wrapper 误判）
	if isLanguageDep(purlLower) {
		return VulnCategoryLanguageDep, RestartActionRebuildApp
	}

	if comp == "" {
		return VulnCategoryOther, RestartActionUnknown
	}

	// 2. Kernel — 必须 reboot
	if isKernel(comp) {
		return VulnCategoryKernel, RestartActionRebootHost
	}

	// 3. Critical shared lib — 实际 reboot
	if isCriticalSharedLib(comp) {
		return VulnCategoryCriticalSharedLib, RestartActionRebootHost
	}

	// 4. Container runtime
	if isContainerRuntime(comp) {
		return VulnCategoryContainerRuntime, RestartActionRestartSpecificService
	}

	// 5. System daemon（先于 cli_tool，避免 openssh-server 被 openssh 前缀误归 cli）
	if isSystemDaemon(comp) {
		return VulnCategorySystemDaemon, RestartActionRestartSpecificService
	}

	// 6. CLI tool
	if isCliTool(comp) {
		return VulnCategoryCliTool, RestartActionNoAction
	}

	// 7. DB service（先于 web_service，避免 mariadb-server 被 web 前缀误判）
	if isDBService(comp) {
		return VulnCategoryDBService, RestartActionRestartSpecificService
	}

	// 8. Web service
	if isWebService(comp) {
		return VulnCategoryWebService, RestartActionRestartSpecificService
	}

	// 9. Shared lib
	if isSharedLib(comp) {
		return VulnCategorySharedLib, RestartActionRestartDependentServices
	}

	return VulnCategoryOther, RestartActionUnknown
}

func isLanguageDep(purlLower string) bool {
	prefixes := []string{
		"pkg:golang/", "pkg:npm/", "pkg:pypi/", "pkg:maven/",
		"pkg:cargo/", "pkg:gem/", "pkg:nuget/", "pkg:composer/",
		"pkg:swift/", "pkg:hex/", "pkg:pub/", "pkg:hackage/",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(purlLower, p) {
			return true
		}
	}
	return false
}

func isKernel(c string) bool {
	if c == "kernel" || c == "linux" {
		return true
	}
	prefixes := []string{
		"kernel-",        // kernel-core/modules/devel/headers/tools
		"linux-image-",   // Debian/Ubuntu
		"linux-headers-", //
		"linux-generic",  // Ubuntu meta
		"linux-modules-", //
		"linux-firmware", //
		"linux-aws",      // AWS optimized
		"linux-azure",    //
		"linux-gcp",      //
		"linux-oracle",   //
		"linux-tools",    //
		"linux-source-",  //
	}
	for _, p := range prefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

func isCriticalSharedLib(c string) bool {
	criticals := map[string]bool{
		"glibc":          true,
		"glibc-common":   true,
		"glibc-langpack": true,
		"libc6":          true,
		"libc-bin":       true,
		"libc6-dev":      true,
		"libc-dev-bin":   true,
		"musl":           true,
		"libstdc++6":     true,
		"libstdc++":      true,
		"libgcc":         true,
		"libgcc1":        true,
		"libgcc-s1":      true,
	}
	return criticals[c]
}

func isContainerRuntime(c string) bool {
	if c == "docker" || c == "docker-ce" || c == "docker-ce-cli" || c == "docker.io" ||
		c == "docker-compose" || c == "containerd" || c == "containerd.io" ||
		c == "runc" || c == "podman" || c == "buildah" || c == "skopeo" ||
		c == "cri-o" || c == "crio" ||
		c == "kubelet" || c == "kubectl" || c == "kubeadm" || c == "kubernetes-cni" {
		return true
	}
	prefixes := []string{"docker-", "containerd-", "kubernetes-"}
	for _, p := range prefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

func isSystemDaemon(c string) bool {
	if c == "systemd" || c == "openssh-server" || c == "openssh-clients" ||
		c == "openssh-sftp-server" || c == "cron" || c == "cronie" || c == "anacron" ||
		c == "polkit" || c == "polkitd" || c == "rsyslog" || c == "syslog-ng" ||
		c == "audit" || c == "auditd" || c == "dbus" || c == "dbus-daemon" ||
		c == "dracut" || c == "selinux-policy" || c == "selinux-policy-targeted" ||
		c == "networkmanager" || c == "network-manager" ||
		c == "firewalld" || c == "iptables" || c == "nftables" ||
		c == "chrony" || c == "chronyd" || c == "ntp" || c == "ntpsec" ||
		c == "atd" || c == "at" {
		return true
	}
	prefixes := []string{
		"systemd-", "openssh-", "polkit-", "audit-", "selinux-",
		"networkmanager-", "network-manager-", "firewalld-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

func isCliTool(c string) bool {
	tools := map[string]bool{
		"sudo": true, "su": true, "tar": true, "gzip": true, "bzip2": true,
		"xz": true, "xz-utils": true, "lzma": true, "zip": true, "unzip": true,
		"rpm": true, "dpkg": true, "apt": true, "apt-get": true, "yum": true, "dnf": true,
		"gnupg": true, "gnupg2": true, "gpg": true, "gpgv": true,
		"ca-certificates": true, "openssl": true, // 注意：openssl CLI 工具，libssl/openssl-libs 才是 shared_lib
		"coreutils": true, "util-linux": true, "shadow-utils": true, "passwd": true,
		"less": true, "vim": true, "vim-common": true, "vim-minimal": true,
		"vim-enhanced": true, "vim-runtime": true, "nano": true,
		"curl": true, "wget": true, "git": true, "git-core": true, "subversion": true,
		"mercurial": true, "rsync": true, "scp": true,
		"jq": true, "diffutils": true, "patch": true, "findutils": true,
		"grep": true, "sed": true, "gawk": true, "awk": true,
		"file": true, "which": true, "tree": true, "lsof": true, "strace": true,
		"htop": true, "iotop": true, "nethogs": true, "tcpdump": true,
		"man-db": true, "info": true, "less-doc": true, "tzdata": true,
		"locales": true, "iputils-ping": true, "iputils": true, "iproute2": true,
		"net-tools": true, "bind-utils": true, "telnet": true, "nc": true,
		"ncurses": true, "ncurses-base": true, "ncurses-bin": true,
		"bash": true, "zsh": true, "fish": true, "dash": true,
	}
	if tools[c] {
		return true
	}
	// vim-7.x.x 这类带子版本前缀
	if strings.HasPrefix(c, "vim-") {
		return true
	}
	return false
}

func isDBService(c string) bool {
	if c == "mysql" || c == "mysql-server" || c == "mysql-client" ||
		c == "mariadb" || c == "mariadb-server" || c == "mariadb-client" ||
		c == "postgresql" || c == "redis" || c == "redis-server" ||
		c == "memcached" || c == "etcd" {
		return true
	}
	prefixes := []string{
		"mysql-", "mariadb-", "postgresql-", "redis-",
		"mongodb", "mongo-", "elasticsearch", "kibana",
		"rabbitmq", "kafka", "zookeeper",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

func isWebService(c string) bool {
	exact := map[string]bool{
		"nginx": true, "apache2": true, "httpd": true, "lighttpd": true, "caddy": true,
		"php": true, "php-fpm": true, "php-cli": true, "php-common": true,
		"python": true, "python2": true, "python3": true,
		"ruby": true, "perl": true, "nodejs": true, "node": true,
		"java": true, "tomcat": true, "tomcat8": true, "tomcat9": true,
		"jetty": true, "jetty9": true, "wildfly": true, "jboss": true,
		"haproxy": true, "varnish": true, "squid": true,
		"bind": true, "bind9": true, "named": true, "dnsmasq": true, "unbound": true,
		"postfix": true, "sendmail": true, "exim4": true, "exim": true,
		"dovecot": true, "samba": true, "vsftpd": true, "proftpd": true,
		"openjdk": true,
	}
	if exact[c] {
		return true
	}
	prefixes := []string{
		"php-", "php7", "php8",
		"python2-", "python3-", "python2.", "python3.",
		"ruby-", "ruby2.", "ruby3.",
		"nodejs-", "perl-",
		"openjdk-", "java-", "tomcat-",
		"nginx-", "httpd-", "apache2-",
		"bind-", "named-", "samba-", "postfix-", "exim-", "dovecot-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

func isSharedLib(c string) bool {
	// 常见 RPM shared lib (无 lib 前缀)
	commonRPMLibs := map[string]bool{
		"openssl-libs": true, "openssl11-libs": true, "openssl3-libs": true,
		"krb5-libs": true, "zlib": true, "bzip2-libs": true, "xz-libs": true,
		"ncurses-libs": true, "readline": true, "pcre": true, "pcre2": true,
		"expat": true, "sqlite": true, "sqlite-libs": true, "libxml2": true,
		"libxslt": true, "libcurl": true, "libssh2": true, "libssh": true,
		"libcrypt": true, "libgcrypt": true, "libgnutls": true, "gnutls": true,
		"libpng": true, "libjpeg-turbo": true, "libtiff": true,
		"libwebp": true, "libvpx": true, "libavcodec": true, "libavformat": true,
	}
	if commonRPMLibs[c] {
		return true
	}
	// Debian/Ubuntu 共享库 lib* 前缀
	if strings.HasPrefix(c, "lib") {
		return true
	}
	// RPM 共享库子包后缀 *-libs / *-libs-debuginfo
	if strings.HasSuffix(c, "-libs") || strings.HasSuffix(c, "-libs-debuginfo") {
		return true
	}
	return false
}
