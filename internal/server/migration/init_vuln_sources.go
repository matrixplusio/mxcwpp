package migration

import (
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// initVulnDataSources 初始化 13 个漏洞数据源 seed。
//
// 幂等：按 name 去重，已存在的 source 不覆盖（保留用户在 UI 改的 enabled/base_url）。
//
// 默认启用策略：
//   - 国外 OS Advisory（RHSA/Rocky/USN/Debian）默认 enabled — 国外服务器可达
//   - CVE 元数据 MITRE/OSV 默认 enabled，NVD 默认 disabled（rate limit + 国外不通风险）
//   - 0day/exploit (CISA KEV / exploit-db) 默认 enabled
//   - 国内 CNNVD/CNVD 默认 disabled — 国外服务器不通 + 403 反爬，国内部署再开
//   - CentOS/Alpine 默认 disabled — 按需开启
func initVulnDataSources(db *gorm.DB, logger *zap.Logger) error {
	defaults := []model.VulnDataSource{
		// 国内官方
		{
			Name: "cnnvd", DisplayName: "国家信息安全漏洞库 (CNNVD)",
			Region: model.VulnSourceRegionCN, Category: model.VulnSourceCategoryCNOfficial,
			Enabled: false, BaseURL: "https://www.cnnvd.org.cn",
			Description: "国家信息安全漏洞库，提供 CNNVD-XXX-XXXX 编号映射。国外服务器可能 403，建议国内部署启用。",
		},
		{
			Name: "cnvd", DisplayName: "国家信息安全漏洞共享平台 (CNVD)",
			Region: model.VulnSourceRegionCN, Category: model.VulnSourceCategoryCNOfficial,
			Enabled: false, BaseURL: "https://www.cnvd.org.cn",
			Description: "国家信息安全漏洞共享平台。无公开 API，需配置第三方镜像数据源。",
		},

		// 国外 OS Advisory
		{
			Name: "rhsa", DisplayName: "Red Hat Security Advisory",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: true, BaseURL: "https://access.redhat.com/security/data/csaf/v2/advisories",
			Description: "Red Hat 官方 CSAF v2 advisory，覆盖 RHEL 7/8/9/10。",
		},
		{
			Name: "rocky-apollo", DisplayName: "Rocky Linux Errata (Apollo)",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: true, BaseURL: "https://apollo.build.resf.org/api/v3",
			Description: "Rocky Linux Apollo Errata API，提供 RLSA 编号 + OS-specific NEVRA。",
		},
		{
			Name: "centos", DisplayName: "CentOS Stream Security",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: false, BaseURL: "",
			Description: "CentOS Stream 9/10 advisory（与 RHEL 同源，默认走 RHSA 不重复同步）。",
		},
		{
			Name: "usn", DisplayName: "Ubuntu Security Notice (USN)",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: true, BaseURL: "https://ubuntu.com/security",
			Description: "Ubuntu 官方 USN，覆盖 18.04/20.04/22.04/24.04 LTS。",
		},
		{
			Name: "debian-tracker", DisplayName: "Debian Security Tracker",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: true, BaseURL: "https://security-tracker.debian.org/tracker",
			Description: "Debian 官方安全追踪器，覆盖 Buster/Bullseye/Bookworm/Trixie。",
		},
		{
			Name: "alpine", DisplayName: "Alpine Linux secdb",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: false, BaseURL: "https://secdb.alpinelinux.org",
			Description: "Alpine Linux secdb，按需启用（容器场景）。",
		},

		// CVE 元数据
		{
			Name: "mitre-cve", DisplayName: "MITRE CVE Records",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryCVEMetadata,
			Enabled: true, BaseURL: "https://cveawg.mitre.org/api/cve",
			Description: "MITRE 官方 CVE 数据库，按 CVE ID 拉取，提供权威 description + CVSS + CWE + references。",
		},
		{
			Name: "nvd", DisplayName: "NVD CVE Database",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryCVEMetadata,
			Enabled: false, BaseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
			APIKeyEnv:   "NVD_API_KEY",
			Description: "NIST 国家漏洞库 API。建议配置 NVD_API_KEY 提速。国外服务器可能受限。",
		},
		{
			Name: "osv", DisplayName: "OSV.dev (Google)",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryCVEMetadata,
			Enabled: true, BaseURL: "https://api.osv.dev",
			Description: "Google OSV 数据库，PURL 精确匹配，覆盖 npm/pypi/golang/maven/OS pkg。",
		},

		// 信创 OS Advisory (P3-1: stub 当前不实际拉数据，待对接)
		{
			Name: "openeuler-sa", DisplayName: "openEuler Security Advisory",
			Region: model.VulnSourceRegionCN, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: false, BaseURL: "https://repo.openeuler.org/security/data/cvrf",
			Description: "openEuler 官方 CVRF 1.2 advisory，覆盖 openEuler 20.03/22.03/24.03 LTS。当前 stub 待 P3-1a-2 实施。",
		},
		{
			Name: "anolis-ansa", DisplayName: "龙蜥 Anolis Security Advisory",
			Region: model.VulnSourceRegionCN, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: false, BaseURL: "https://anas.openanolis.org/api",
			Description: "龙蜥 Anolis OS 官方 ANSA advisory。当前 stub 待 P3-1b-2 实施。",
		},
		{
			Name: "kylin-sa", DisplayName: "麒麟 Kylin Security Advisory",
			Region: model.VulnSourceRegionCN, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: false, BaseURL: "",
			Description: "麒麟 V10 安全公告。官方无公开 API，需对接商业镜像源。当前 stub 待 P3-1c-2 实施。",
		},
		{
			Name: "uos-sa", DisplayName: "统信 UOS Security Advisory",
			Region: model.VulnSourceRegionCN, Category: model.VulnSourceCategoryOSAdvisory,
			Enabled: false, BaseURL: "",
			Description: "统信 UOS 安全公告（基于 Debian 衍生）。官方无公开 API，需对接商业镜像源。当前 stub。",
		},

		// 0day / Exploit
		{
			Name: "cisa-kev", DisplayName: "CISA Known Exploited Vulnerabilities",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryExploit,
			Enabled: true, BaseURL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			Description: "CISA 已被剥削漏洞清单，标记 in_kev=true（优先修复指标）。",
		},
		{
			Name: "exploit-db", DisplayName: "Exploit Database (0day)",
			Region: model.VulnSourceRegionGlobal, Category: model.VulnSourceCategoryExploit,
			Enabled: true, BaseURL: "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
			Description: "Exploit-DB 公开 PoC 库，标记 has_exploit=true 并补 exploit_ref。",
		},
	}

	created := 0
	for _, src := range defaults {
		var existing model.VulnDataSource
		err := db.Where("name = ?", src.Name).First(&existing).Error
		if err == nil {
			continue // 已存在，保留用户配置
		}
		if err != gorm.ErrRecordNotFound {
			return err
		}
		if err := db.Create(&src).Error; err != nil {
			logger.Warn("创建漏洞数据源失败",
				zap.String("name", src.Name), zap.Error(err))
			continue
		}
		created++
	}
	if created > 0 {
		logger.Info("漏洞数据源 seed 初始化完成", zap.Int("created", created))
	}
	return nil
}
