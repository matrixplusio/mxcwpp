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

// VulnCategory 10 类枚举（写入 vulnerabilities.vuln_category）
const (
	VulnCategoryKernel            = "kernel"
	VulnCategoryCriticalSharedLib = "critical_shared_lib" // glibc/libc6/musl — 实际等同 reboot
	VulnCategorySharedLib         = "shared_lib"          // openssl/zlib/libxml2 — 升级后需 restart 依赖服务
	VulnCategorySystemDaemon      = "system_daemon"       // systemd/sshd/cron/NetworkManager/asterisk
	VulnCategoryCliTool           = "cli_tool"            // sudo/tar/rpm/curl/ffmpeg/imagemagick/wireshark — 无需重启
	VulnCategoryWebService        = "web_service"         // nginx/apache/php-fpm/chromium/firefox/wordpress/mediawiki
	VulnCategoryDBService         = "db_service"          // mysql/postgres/redis/mongodb — 重启 = DB 中断
	VulnCategoryContainerRuntime  = "container_runtime"   // docker/containerd/runc/kubelet
	VulnCategoryVirtualization    = "virtualization"      // xen/qemu/kvm/libvirt — 升级 hypervisor 影响所有 VM
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

// AssetType 资产维度漏洞分类（写入 host_vulnerabilities.asset_type）
// 决定修复责任方和修复路径:
//
//	os         → 运维 yum/apt patch (OS RPM/DEB)
//	middleware → DBA/SRE 升级中间件包 (jar/binary_probe 主机本体服务)
//	app        → 研发 rebuild 业务程序 (embedded scope, Go/Python/Node 静态依赖)
//	container  → 镜像维护者 rebuild image (container scope, docker 容器内 SBOM)
//	image      → 镜像维护者 (image_scans 来源)
//	unknown    → 软件关联缺失,数据治理
const (
	AssetTypeOS         = "os"
	AssetTypeMiddleware = "middleware"
	AssetTypeApp        = "app"
	AssetTypeContainer  = "container"
	AssetTypeImage      = "image"
	AssetTypeUnknown    = "unknown"
)

// FixOwner 修复责任方枚举（写入 host_vulnerabilities.fix_owner）
const (
	FixOwnerOps             = "ops"              // 运维: os asset + 系统类 vuln_category
	FixOwnerDev             = "dev"              // 研发: app asset + language_dep
	FixOwnerDBA             = "dba"              // DBA: middleware + db_service
	FixOwnerSRE             = "sre"              // SRE/中间件: middleware + web_service/container_runtime
	FixOwnerImageMaintainer = "image_maintainer" // 镜像维护者: container/image
	FixOwnerCloudProvider   = "cloud_provider"   // 云厂商 GCP/AWS/Azure 系统 agent
	FixOwnerAPMVendor       = "apm_vendor"       // SkyWalking/Datadog 等 APM 探针
	FixOwnerPlatformTeam    = "platform_team"    // mxsec 平台自身组件
	FixOwnerUnknown         = "unknown"
)

// Subscope 细分类(P-vuln-classify Phase4): host_vulnerabilities.subscope 字段
//
// 用于区分系统组件 vs 业务: 比如 golang.org/x/crypto v0.38.0 同一个 CVE,
// 如果来自 /usr/bin/google_osconfig_agent (GCP 自带 agent) 归 cloud_agent,
// 如果来自 /opt/app/myservice (用户业务 binary) 才归 business_binary。
// 决定 fix_owner 责任方,避免把 GCP 系统组件漏洞甩锅给业务研发。
const (
	SubscopeCloudAgent      = "cloud_agent"      // GCP/AWS/Azure/Aliyun 自带
	SubscopeMonitoringAgent = "monitoring_agent" // SkyWalking/Datadog/Prometheus exporter
	SubscopeSecurityAgent   = "security_agent"   // mxsec-agent/EDR/ClamAV
	SubscopeSystemTool      = "system_tool"      // OS 自带工具 buildah/podman/skopeo/runc/git (RPM 装的 Go binary)
	SubscopeSystemLib       = "system_lib"       // glibc/libssl 关键共享库
	SubscopeOSPackage       = "os_package"       // 主流 OS RPM/DEB
	SubscopeBusinessBinary  = "business_binary"  // 真业务 Go/Python/Node
	SubscopeBusinessJar     = "business_jar"     // 真业务 Java jar
	SubscopeUnknown         = "unknown"
)

// systemPathPatterns subscope 路径前缀匹配规则,排序按特异性(具体路径优先)
var systemPathPatterns = []struct {
	prefix   string
	subscope string
}{
	// GCP
	{"/usr/bin/google_osconfig_agent", SubscopeCloudAgent},
	{"/usr/bin/google_guest_agent", SubscopeCloudAgent},
	{"/usr/bin/google_metadata_script_runner", SubscopeCloudAgent},
	{"/usr/sbin/google_metadata_script_runner", SubscopeCloudAgent},
	{"/usr/bin/google_network_daemon", SubscopeCloudAgent},
	{"/usr/bin/google_accounts_daemon", SubscopeCloudAgent},
	{"/usr/bin/google-fluentd", SubscopeCloudAgent},
	{"/usr/bin/google-fluentbit", SubscopeCloudAgent},
	// AWS
	{"/usr/bin/amazon-ssm-agent", SubscopeCloudAgent},
	{"/snap/amazon-ssm-agent/", SubscopeCloudAgent},
	{"/usr/sbin/aws-cli", SubscopeCloudAgent},
	// Azure
	{"/usr/sbin/waagent", SubscopeCloudAgent},
	{"/var/lib/waagent/", SubscopeCloudAgent},
	// Aliyun / Tencent
	{"/usr/local/share/aliyun-assist/", SubscopeCloudAgent},
	{"/usr/local/cloudmonitor/", SubscopeCloudAgent},
	{"/usr/local/qcloud/", SubscopeCloudAgent},

	// 监控探针
	{"/opt/skywalking-agent/", SubscopeMonitoringAgent},
	{"/opt/datadog-agent/", SubscopeMonitoringAgent},
	{"/opt/newrelic/", SubscopeMonitoringAgent},
	{"/opt/dynatrace/", SubscopeMonitoringAgent},
	{"/opt/appdynamics/", SubscopeMonitoringAgent},
	{"/usr/local/bin/node_exporter", SubscopeMonitoringAgent},
	{"/usr/local/bin/promtail", SubscopeMonitoringAgent},
	{"/usr/bin/node_exporter", SubscopeMonitoringAgent},
	{"/usr/sbin/filebeat", SubscopeMonitoringAgent},
	{"/usr/share/filebeat/", SubscopeMonitoringAgent},
	{"/opt/td-agent/", SubscopeMonitoringAgent},
	{"/usr/sbin/telegraf", SubscopeMonitoringAgent},

	// 安全平台
	{"/usr/bin/mxsec-agent", SubscopeSecurityAgent},
	{"/var/lib/mxsec-agent/", SubscopeSecurityAgent},
	{"/var/lib/mxsec/", SubscopeSecurityAgent},
	{"/usr/sbin/clamd", SubscopeSecurityAgent},
	{"/usr/bin/clamav", SubscopeSecurityAgent},
	{"/usr/bin/freshclam", SubscopeSecurityAgent},
	{"/opt/wazuh-agent/", SubscopeSecurityAgent},
	{"/opt/falcon-sensor/", SubscopeSecurityAgent},

	// OS 自带 system tool (RPM 装的 Go binary,无业务责任)
	{"/usr/bin/buildah", SubscopeSystemTool},
	{"/usr/bin/podman", SubscopeSystemTool},
	{"/usr/bin/skopeo", SubscopeSystemTool},
	{"/usr/bin/runc", SubscopeSystemTool},
	{"/usr/sbin/runc", SubscopeSystemTool},
	{"/usr/bin/crun", SubscopeSystemTool},
	{"/usr/libexec/podman/", SubscopeSystemTool},
	{"/usr/bin/conmon", SubscopeSystemTool},
	{"/usr/bin/git", SubscopeSystemTool},
	{"/usr/bin/git-remote-helper", SubscopeSystemTool},
	{"/usr/bin/helm", SubscopeSystemTool},
	{"/usr/bin/kubectl", SubscopeSystemTool},
	{"/usr/bin/etcdctl", SubscopeSystemTool},
	{"/usr/sbin/etcd", SubscopeSystemTool},
	{"/usr/local/go/", SubscopeSystemTool},
	{"/usr/bin/cri-tools", SubscopeSystemTool},
	{"/usr/bin/cilium", SubscopeSystemTool},
	{"/usr/bin/hubble", SubscopeSystemTool},
}

// DeriveSubscope 按 software 的 host_binary_path + scope/handler/component 推导细分
//   - hostBinaryPath: 嵌入式依赖的宿主 binary 路径(scope=embedded 时存在)
//   - scope: software.scope (system/embedded/container)
//   - sourceHandler: collector 模块 (rpm/dpkg/jar_scanner/go_buildinfo/...)
//   - component: 包名(可用于识别 system_lib)
func DeriveSubscope(hostBinaryPath, scope, sourceHandler, component string) string {
	bp := strings.TrimSpace(hostBinaryPath)
	if bp != "" {
		for _, p := range systemPathPatterns {
			if strings.HasPrefix(bp, p.prefix) {
				return p.subscope
			}
		}
	}
	s := strings.ToLower(strings.TrimSpace(scope))
	h := strings.ToLower(strings.TrimSpace(sourceHandler))
	comp := strings.ToLower(strings.TrimSpace(component))

	// jar 路径不匹配系统目录 → 业务 jar
	if h == "jar_scanner" {
		return SubscopeBusinessJar
	}
	// 系统库
	if isCriticalSharedLib(comp) || isSharedLib(comp) {
		return SubscopeSystemLib
	}
	// OS 包管理
	switch h {
	case "rpm", "dpkg", "apk", "pacman", "portage":
		return SubscopeOSPackage
	}
	// embedded 路径不匹配系统 → 业务 binary
	if s == "embedded" {
		return SubscopeBusinessBinary
	}
	// system + handler 空 → 兜底 OS
	if s == "system" || s == "" {
		return SubscopeOSPackage
	}
	return SubscopeUnknown
}

// DeriveAssetType 根据 software.scope + source_handler 推导资产类型
// scope=embedded 必然是 app(静态依赖,无论 handler);
// scope=container 必然是 container;
// scope=system 按 handler 区分 os(RPM/DEB/APK)和 middleware(jar/binary_probe)
func DeriveAssetType(scope, sourceHandler string) string {
	scope = strings.ToLower(strings.TrimSpace(scope))
	h := strings.ToLower(strings.TrimSpace(sourceHandler))
	switch scope {
	case "embedded":
		return AssetTypeApp
	case "container":
		return AssetTypeContainer
	case "system", "":
		// OS 包管理器
		switch h {
		case "rpm", "dpkg", "apk", "pacman", "portage":
			return AssetTypeOS
		case "jar_scanner", "binary_probe":
			return AssetTypeMiddleware
		case "go_buildinfo", "python", "node", "ruby", "php":
			// system scope + 语言运行时 → 主机本体的 Go/Python 服务（中间件层）
			return AssetTypeMiddleware
		case "container_sbom":
			return AssetTypeContainer
		}
	}
	if scope == "" && h == "" {
		return AssetTypeUnknown
	}
	return AssetTypeOS // 兜底:scope=system 但 handler 缺失,大概率 OS 包
}

// DeriveFixOwner 根据 subscope(优先)+ asset_type + vuln_category 推导修复责任方
// subscope 是更精确的源,如果命中云厂商/监控/安全平台/系统工具,直接定 owner,不再走 asset_type 兜底
func DeriveFixOwner(assetType, vulnCategory, subscope string) string {
	switch subscope {
	case SubscopeCloudAgent:
		return FixOwnerCloudProvider
	case SubscopeMonitoringAgent:
		return FixOwnerAPMVendor
	case SubscopeSecurityAgent:
		return FixOwnerPlatformTeam
	case SubscopeSystemTool:
		return FixOwnerOps // OS 自带工具(buildah/podman),运维 dnf update 处理
	}
	switch assetType {
	case AssetTypeApp:
		return FixOwnerDev
	case AssetTypeContainer, AssetTypeImage:
		return FixOwnerImageMaintainer
	case AssetTypeOS:
		switch vulnCategory {
		case VulnCategoryDBService:
			return FixOwnerDBA
		case VulnCategoryWebService, VulnCategoryContainerRuntime, VulnCategoryVirtualization:
			return FixOwnerSRE
		}
		return FixOwnerOps
	case AssetTypeMiddleware:
		switch vulnCategory {
		case VulnCategoryDBService:
			return FixOwnerDBA
		case VulnCategoryWebService, VulnCategoryContainerRuntime:
			return FixOwnerSRE
		case VulnCategoryLanguageDep:
			return FixOwnerDev
		}
		return FixOwnerSRE
	}
	return FixOwnerUnknown
}

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

	// 4.5 Virtualization (xen/qemu/kvm/libvirt)
	if isVirtualization(comp) {
		return VulnCategoryVirtualization, RestartActionRestartSpecificService
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

// isVirtualization Hypervisor / VM 管理软件（升级影响所有 guest VM）
func isVirtualization(c string) bool {
	exact := map[string]bool{
		"xen": true, "xen-hypervisor": true, "xen-utils-common": true,
		"qemu": true, "qemu-kvm": true, "qemu-system": true, "qemu-system-x86": true,
		"qemu-system-arm": true, "qemu-system-common": true, "qemu-utils": true,
		"qemu-guest-agent": true, "qemu-img": true,
		"libvirt": true, "libvirt-clients": true, "libvirt-daemon": true,
		"libvirt-daemon-system": true, "libvirt-bin": true,
		"virt-manager": true, "virt-install": true, "virt-viewer": true,
		"kvm": true, "kvmtool": true,
		"open-vm-tools": true, "vmware-tools": true,
		"virtualbox": true, "virtualbox-guest-utils": true,
		"vagrant": true,
	}
	if exact[c] {
		return true
	}
	prefixes := []string{
		"xen-", "qemu-", "libvirt-", "virt-",
	}
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
		c == "atd" || c == "at" ||
		c == "asterisk" || c == "freeswitch" || c == "kamailio" {
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
		// 多媒体 / 图形 / 抓包 工具（CLI 使用，无 daemon）
		"ffmpeg": true, "imagemagick": true, "graphicsmagick": true,
		"wireshark": true, "wireshark-cli": true, "tshark": true,
		"tiff": true, "libtiff": true, "tiff-tools": true,
		"gpac": true, "mediainfo": true,
		"binutils": true, "gcc": true, "g++": true, "make": true, "cmake": true,
		"glibc-langpack-en": true, "glibc-langpack": true,
		"poppler-utils": true, "ghostscript": true, "pdftk": true,
	}
	if tools[c] {
		return true
	}
	prefixes := []string{
		"vim-",            // vim-7.x.x
		"binutils-",       // binutils-aarch64 等交叉编译
		"gcc-",            // gcc-9 / gcc-aarch64
		"glibc-langpack-", // glibc-langpack-zh
		"poppler-",        // poppler-utils 等
		"ghostscript-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
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
		// 浏览器（HTTP client/JS engine — 仍归 web_service，restart 影响浏览进程）
		"chromium": true, "chromium-browser": true, "chromium-bsu": true,
		"firefox": true, "firefox-esr": true, "thunderbird": true,
		"webkit2gtk": true, "webkitgtk": true,
		// CMS / web 应用
		"wordpress": true, "mediawiki": true, "drupal": true, "drupal7": true,
		"joomla": true, "phpmyadmin": true, "phpbb": true,
		// 邮件 web 工具
		"roundcube": true, "squirrelmail": true,
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
