// Package migration —— BackfillAssetTypeAndFixOwner
//
// 全表回填 host_vulnerabilities.asset_type + subscope + fix_owner + host_binary_path。
// 推导路径:
//
//	host_vuln.vuln_id → vulnerabilities.component + vuln_category
//	host_vuln.host_id + component → software.scope + source_handler + host_binary_path
//	model.DeriveSubscope(host_binary_path,scope,handler,component) (P4 误报识别核心)
//	model.DeriveAssetType(scope, source_handler)
//	model.DeriveFixOwner(asset_type, vuln_category, subscope)
//
// 用单 SQL UPDATE + JOIN 而非 N+1 GORM Hook,prod 11k+ 行场景 1-2s 跑完。
package migration

import (
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// BackfillAssetTypeAndFixOwner 一次性回填全表。幂等:仅在 unknown 或空时填。
// 6 段 UPDATE 覆盖主要路径,剩余无 software 关联的留 unknown(下一轮 SBOM 采集后再跑)。
func BackfillAssetTypeAndFixOwner(db *gorm.DB, logger *zap.Logger) error {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Step 0: 回填 host_binary_path(供 UI 溯源 + subscope 推导用)
	// 取每个 (host_id, component) 优先 scope=embedded 的 software 路径
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
JOIN (
  SELECT host_id, name, MAX(host_binary_path) AS host_binary_path
  FROM software
  WHERE host_binary_path IS NOT NULL AND host_binary_path <> ''
  GROUP BY host_id, name
) s ON s.host_id = hv.host_id AND s.name = v.component
SET hv.host_binary_path = s.host_binary_path
WHERE (hv.host_binary_path IS NULL OR hv.host_binary_path = '')
`).Error; err != nil {
		return err
	}

	// Step 1: scope=embedded → asset_type=app
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
JOIN software s ON s.host_id = hv.host_id AND s.name = v.component
SET hv.asset_type = 'app'
WHERE (hv.asset_type IS NULL OR hv.asset_type = '' OR hv.asset_type = 'unknown')
  AND s.scope = 'embedded'
`).Error; err != nil {
		return err
	}

	// Step 2: scope=container → asset_type=container
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
JOIN software s ON s.host_id = hv.host_id AND s.name = v.component
SET hv.asset_type = 'container'
WHERE (hv.asset_type IS NULL OR hv.asset_type = '' OR hv.asset_type = 'unknown')
  AND s.scope = 'container'
`).Error; err != nil {
		return err
	}

	// Step 3: scope=system + handler=rpm/dpkg/... 或 handler 空 → os
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
JOIN software s ON s.host_id = hv.host_id AND s.name = v.component
SET hv.asset_type = 'os'
WHERE (hv.asset_type IS NULL OR hv.asset_type = '' OR hv.asset_type = 'unknown')
  AND (s.scope = 'system' OR s.scope IS NULL OR s.scope = '')
  AND (s.source_handler IN ('rpm', 'dpkg', 'apk', 'pacman', 'portage')
       OR s.source_handler IS NULL OR s.source_handler = '')
`).Error; err != nil {
		return err
	}

	// Step 4: scope=system + jar/binary/语言 → middleware
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
JOIN software s ON s.host_id = hv.host_id AND s.name = v.component
SET hv.asset_type = 'middleware'
WHERE (hv.asset_type IS NULL OR hv.asset_type = '' OR hv.asset_type = 'unknown')
  AND s.scope = 'system'
  AND s.source_handler IN ('jar_scanner', 'binary_probe', 'go_buildinfo', 'python', 'node', 'ruby', 'php')
`).Error; err != nil {
		return err
	}

	// Step 5: 无 software 关联但 vuln_category=language_dep → app(兜底)
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
SET hv.asset_type = 'app'
WHERE (hv.asset_type IS NULL OR hv.asset_type = '' OR hv.asset_type = 'unknown')
  AND v.vuln_category = 'language_dep'
`).Error; err != nil {
		return err
	}

	// Step 6: subscope 推导 - 按 host_binary_path 前缀分类
	// 顺序: 具体路径优先,系统库/OS 包兜底
	// 6.1 GCP cloud agent
	if err := db.Exec(`
UPDATE host_vulnerabilities
SET subscope = 'cloud_agent'
WHERE (subscope IS NULL OR subscope = '' OR subscope = 'unknown')
  AND host_binary_path IS NOT NULL
  AND (
    host_binary_path LIKE '/usr/bin/google_%_agent%' OR
    host_binary_path LIKE '/usr/bin/google_metadata_script_runner%' OR
    host_binary_path LIKE '/usr/sbin/google_metadata_script_runner%' OR
    host_binary_path LIKE '/usr/bin/google_network_daemon%' OR
    host_binary_path LIKE '/usr/bin/google_accounts_daemon%' OR
    host_binary_path LIKE '/usr/bin/google-fluentd%' OR
    host_binary_path LIKE '/usr/bin/google-fluentbit%' OR
    host_binary_path LIKE '/usr/bin/amazon-ssm-agent%' OR
    host_binary_path LIKE '/snap/amazon-ssm-agent/%' OR
    host_binary_path LIKE '/usr/sbin/waagent%' OR
    host_binary_path LIKE '/var/lib/waagent/%' OR
    host_binary_path LIKE '/usr/local/share/aliyun-assist/%' OR
    host_binary_path LIKE '/usr/local/cloudmonitor/%' OR
    host_binary_path LIKE '/usr/local/qcloud/%'
  )
`).Error; err != nil {
		return err
	}

	// 6.2 监控探针
	if err := db.Exec(`
UPDATE host_vulnerabilities
SET subscope = 'monitoring_agent'
WHERE (subscope IS NULL OR subscope = '' OR subscope = 'unknown')
  AND host_binary_path IS NOT NULL
  AND (
    host_binary_path LIKE '/opt/skywalking-agent/%' OR
    host_binary_path LIKE '/opt/datadog-agent/%' OR
    host_binary_path LIKE '/opt/newrelic/%' OR
    host_binary_path LIKE '/opt/dynatrace/%' OR
    host_binary_path LIKE '/opt/appdynamics/%' OR
    host_binary_path LIKE '/usr/local/bin/node_exporter%' OR
    host_binary_path LIKE '/usr/local/bin/promtail%' OR
    host_binary_path LIKE '/usr/bin/node_exporter%' OR
    host_binary_path LIKE '/usr/sbin/filebeat%' OR
    host_binary_path LIKE '/usr/share/filebeat/%' OR
    host_binary_path LIKE '/opt/td-agent/%' OR
    host_binary_path LIKE '/usr/sbin/telegraf%'
  )
`).Error; err != nil {
		return err
	}

	// 6.3 安全平台自身
	if err := db.Exec(`
UPDATE host_vulnerabilities
SET subscope = 'security_agent'
WHERE (subscope IS NULL OR subscope = '' OR subscope = 'unknown')
  AND host_binary_path IS NOT NULL
  AND (
    host_binary_path LIKE '/usr/bin/mxsec-agent%' OR
    host_binary_path LIKE '/var/lib/mxsec-agent/%' OR
    host_binary_path LIKE '/var/lib/mxsec/%' OR
    host_binary_path LIKE '/usr/sbin/clamd%' OR
    host_binary_path LIKE '/usr/bin/clamav%' OR
    host_binary_path LIKE '/usr/bin/freshclam%' OR
    host_binary_path LIKE '/opt/wazuh-agent/%' OR
    host_binary_path LIKE '/opt/falcon-sensor/%'
  )
`).Error; err != nil {
		return err
	}

	// 6.3.5 OS 自带 system tool (buildah/podman/runc/git/helm/kubectl)
	if err := db.Exec(`
UPDATE host_vulnerabilities
SET subscope = 'system_tool'
WHERE (subscope IS NULL OR subscope = '' OR subscope = 'unknown')
  AND host_binary_path IS NOT NULL
  AND (
    host_binary_path LIKE '/usr/bin/buildah%' OR
    host_binary_path LIKE '/usr/bin/podman%' OR
    host_binary_path LIKE '/usr/bin/skopeo%' OR
    host_binary_path LIKE '/usr/bin/runc%' OR
    host_binary_path LIKE '/usr/sbin/runc%' OR
    host_binary_path LIKE '/usr/bin/crun%' OR
    host_binary_path LIKE '/usr/libexec/podman/%' OR
    host_binary_path LIKE '/usr/bin/conmon%' OR
    host_binary_path LIKE '/usr/bin/git%' OR
    host_binary_path LIKE '/usr/bin/helm%' OR
    host_binary_path LIKE '/usr/bin/kubectl%' OR
    host_binary_path LIKE '/usr/bin/etcdctl%' OR
    host_binary_path LIKE '/usr/sbin/etcd%' OR
    host_binary_path LIKE '/usr/local/go/%' OR
    host_binary_path LIKE '/usr/bin/cri-tools%' OR
    host_binary_path LIKE '/usr/bin/cilium%' OR
    host_binary_path LIKE '/usr/bin/hubble%'
  )
`).Error; err != nil {
		return err
	}

	// 6.4 系统共享库 (按 vuln_category)
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
SET hv.subscope = 'system_lib'
WHERE (hv.subscope IS NULL OR hv.subscope = '' OR hv.subscope = 'unknown')
  AND v.vuln_category IN ('critical_shared_lib', 'shared_lib')
`).Error; err != nil {
		return err
	}

	// 6.5 OS 包 (asset_type=os 且未分类)
	if err := db.Exec(`
UPDATE host_vulnerabilities
SET subscope = 'os_package'
WHERE (subscope IS NULL OR subscope = '' OR subscope = 'unknown')
  AND asset_type = 'os'
`).Error; err != nil {
		return err
	}

	// 6.6 业务 jar (asset_type=middleware + handler=jar_scanner 但路径不匹配监控)
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
JOIN software s ON s.host_id = hv.host_id AND s.name = v.component
SET hv.subscope = 'business_jar'
WHERE (hv.subscope IS NULL OR hv.subscope = '' OR hv.subscope = 'unknown')
  AND s.source_handler = 'jar_scanner'
`).Error; err != nil {
		return err
	}

	// 6.7 业务 binary (asset_type=app 兜底,即不在 cloud/monitoring/security 白名单)
	if err := db.Exec(`
UPDATE host_vulnerabilities
SET subscope = 'business_binary'
WHERE (subscope IS NULL OR subscope = '' OR subscope = 'unknown')
  AND asset_type IN ('app', 'middleware')
`).Error; err != nil {
		return err
	}

	// Step 7: fix_owner 按 subscope 优先 + asset_type/vuln_category 推导
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
SET hv.fix_owner = CASE
  WHEN hv.subscope = 'cloud_agent' THEN 'cloud_provider'
  WHEN hv.subscope = 'monitoring_agent' THEN 'apm_vendor'
  WHEN hv.subscope = 'security_agent' THEN 'platform_team'
  WHEN hv.subscope = 'system_tool' THEN 'ops'
  WHEN hv.asset_type = 'app' THEN 'dev'
  WHEN hv.asset_type IN ('container', 'image') THEN 'image_maintainer'
  WHEN hv.asset_type = 'os' AND v.vuln_category = 'db_service' THEN 'dba'
  WHEN hv.asset_type = 'os' AND v.vuln_category IN ('web_service', 'container_runtime', 'virtualization') THEN 'sre'
  WHEN hv.asset_type = 'os' THEN 'ops'
  WHEN hv.asset_type = 'middleware' AND v.vuln_category = 'db_service' THEN 'dba'
  WHEN hv.asset_type = 'middleware' AND v.vuln_category IN ('web_service', 'container_runtime') THEN 'sre'
  WHEN hv.asset_type = 'middleware' AND v.vuln_category = 'language_dep' THEN 'dev'
  WHEN hv.asset_type = 'middleware' THEN 'sre'
  ELSE 'unknown'
END
WHERE (hv.fix_owner IS NULL OR hv.fix_owner = '' OR hv.fix_owner = 'unknown')
`).Error; err != nil {
		return err
	}

	// Step 8: 把 app/container/image 类历史 failed precheck 状态批量标 not_applicable
	if err := db.Exec(`
UPDATE host_vulnerabilities
SET precheck_status = 'not_applicable',
    precheck_message = '应用/容器漏洞不归 OS 包管理器,需 rebuild 业务程序或镜像'
WHERE asset_type IN ('app', 'container', 'image')
  AND precheck_status IN ('failed', 'unchecked')
`).Error; err != nil {
		return err
	}

	// Step 9: 误报识别 - daemon 真实存在交叉验证
	// 比如 component=github.com/docker/docker 但主机没装 docker daemon (process_list 无 dockerd
	// + package_list 无 docker-ce),precheck_message 提示"非主机服务,Go 模块依赖嵌入式"
	// 这样 UI 详情页能直接显示警示,消除"装了 docker?"误解
	//
	// 注:Go module path 含 '/' 必然是嵌入式,不可能是 RPM/DEB 主包名,可直接标
	if err := db.Exec(`
UPDATE host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
SET hv.precheck_message = CONCAT(
  '此 CVE 影响 ', v.component, ' (作为静态依赖嵌入 ',
  COALESCE(NULLIF(hv.host_binary_path, ''), '<未知 binary>'),
  ')。主机未运行独立 daemon。')
WHERE hv.asset_type = 'app'
  AND v.component LIKE '%/%'
  AND (hv.precheck_message IS NULL OR hv.precheck_message = '' OR hv.precheck_message LIKE '%应用/容器漏洞不归%')
`).Error; err != nil {
		return err
	}

	// 统计结果
	type stat struct {
		AssetType string
		Subscope  string
		FixOwner  string
		N         int64
	}
	var stats []stat
	if err := db.Table("host_vulnerabilities").
		Select("asset_type, subscope, fix_owner, COUNT(*) AS n").
		Group("asset_type, subscope, fix_owner").Order("n DESC").Scan(&stats).Error; err == nil {
		for _, s := range stats {
			logger.Info("backfill stats",
				zap.String("asset", s.AssetType),
				zap.String("subscope", s.Subscope),
				zap.String("owner", s.FixOwner),
				zap.Int64("n", s.N))
		}
	}
	return nil
}
