// Package model — OS-specific advisory package fix
package model

// AdvisoryPackage 一条 CVE × OS × source × pkg × arch 的精确修复版本。
//
// 设计目的：解决"同一 CVE 在不同 OS 的 fixed_version 不同"导致的扫描漏报。
//
// 旧模型：vulnerabilities.fixed_version 是单值，多 OS 数据只能存一种（RHSA el10
// 覆盖 Rocky el9），扫描 Rocky 9 host 时 NEVRA 比对失败 → 漏报。
//
// 新模型：advisory_packages 按 (cve_id × source × os_family × os_major × pkg_name
// × arch) 唯一存储，scanner / matcher / precheck 按 host OS 维度精确查找。
//
// 数据流：
//
//	RHSA Source  → advisory_packages (cve_id, source=rhsa,       os=rhel,  major=10, fix=el10_1)
//	Rocky Source → advisory_packages (cve_id, source=rocky-apollo,os=rocky,major=9,  fix=el9_8)
//	Matcher      → 按 host.OSFamily/OSMajor 查匹配行做 NEVRA 比对
//
// 与 vulnerabilities 关系：vulnerabilities 行存 CVE 元数据（描述/CVSS/CWE 等），
// advisory_packages 行存"如何修"。一个 CVE 对应多个 advisory_packages（多 OS / 多源）。
type AdvisoryPackage struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       uint   `gorm:"primaryKey;column:id;autoIncrement" json:"id"`

	// CVE 关联（cve_id 不强约束 FK，便于 source 先到 vuln 未到的情况）
	CveID string `gorm:"column:cve_id;type:varchar(50);not null;index:idx_ap_cve" json:"cveId"`

	// 数据源标识（rhsa / rocky-apollo / debian-tracker / alpine / osv / nvd / ubuntu / centos / 信创...）
	Source string `gorm:"column:source;type:varchar(32);not null" json:"source"`

	// 上游公告 ID（RHSA-2025:1234 / RLSA-2026:5678 / DSA-... 用于 UI 引用）
	// Alpine source 拼 "Alpine-<branch>-<pkgName>-<fixedVer>" 易超 64 字符，留 255 余量
	SourceAdvisoryID string `gorm:"column:source_advisory_id;type:varchar(255);index" json:"sourceAdvisoryId"`

	// OS 归属（按 host OS 维度查找用）
	//   OSFamily: rhel/rocky/centos/almalinux/oraclelinux/debian/ubuntu/alpine/openeuler/anolis/kylin/uos
	//   OSMajor:  9 / 10 / 11 / "" （""=未明确 OS 主版本，仅靠 ecosystem 匹配）
	OSFamily string `gorm:"column:os_family;type:varchar(32);not null;default:'';index:idx_ap_os" json:"osFamily"`
	OSMajor  string `gorm:"column:os_major;type:varchar(16);not null;default:'';index:idx_ap_os" json:"osMajor"`

	// Ecosystem（非 OS pkg 用，如 npm / pypi / maven / golang），与 OSFamily 互斥
	Ecosystem string `gorm:"column:ecosystem;type:varchar(64);default:'';index" json:"ecosystem"`

	// pkg 标识
	PkgName string `gorm:"column:pkg_name;type:varchar(200);not null;index:idx_ap_lookup" json:"pkgName"`
	Arch    string `gorm:"column:arch;type:varchar(16);default:'';index:idx_ap_lookup" json:"arch"`

	// 修复后的精确版本（NEVRA：epoch:version-release，或 dpkg/语言包格式）
	FixedVersion string `gorm:"column:fixed_version;type:varchar(200);not null" json:"fixedVersion"`

	// Confidence: 与 Vulnerability.Confidence 同义，便于 source 优先级控制
	Confidence string `gorm:"column:confidence;type:varchar(10);default:'high'" json:"confidence"`

	// Severity（advisory 维度，可能与 CVE 不同因 OS 厂商各自评估）
	Severity string `gorm:"column:severity;type:varchar(20);default:''" json:"severity"`

	// IssuedAt 厂商公告时间，便于按时间窗清理过期数据
	IssuedAt *LocalTime `gorm:"column:issued_at;type:timestamp" json:"issuedAt,omitempty"`

	CreatedAt LocalTime `gorm:"column:created_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt LocalTime `gorm:"column:updated_at;type:timestamp;default:CURRENT_TIMESTAMP" json:"updatedAt"`
}

// TableName 指定表名
func (AdvisoryPackage) TableName() string {
	return "advisory_packages"
}
