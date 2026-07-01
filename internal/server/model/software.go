// Package model 提供数据库模型定义
package model

// Software 软件包资产模型
type Software struct {
	TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`
	ID       string `gorm:"primaryKey;column:id;type:varchar(128);not null" json:"id"`
	HostID   string `gorm:"column:host_id;type:varchar(64);not null;index;index:idx_sw_host_name,priority:1" json:"host_id"`
	// idx_sw_host_name：cleanup/CleanupAlreadyPatched/precheck 均按 (host_id,name) join software 判包
	// 是否安装；仅 host_id 单列索引时每主机需内存扫全部包(~800)，20k host_vuln 全表 anti-join 达 74s。
	Name    string `gorm:"column:name;type:varchar(255);not null;index:idx_sw_host_name,priority:2" json:"name"`
	Version string `gorm:"column:version;type:varchar(100)" json:"version"`
	// Epoch RPM 的 EPOCH 字段（不存在则为空或 "0"）。NEVRA 比较时若 epoch 不同则直接定胜负。
	Epoch string `gorm:"column:epoch;type:varchar(16)" json:"epoch"`
	// Release RPM 的 RELEASE 字段（如 "284.11.1.el9_2"）。NEVRA 比较 release 段。
	Release      string `gorm:"column:release;type:varchar(100)" json:"release"`
	Architecture string `gorm:"column:architecture;type:varchar(50)" json:"architecture"`
	PackageType  string `gorm:"column:package_type;type:varchar(50);not null" json:"package_type"` // rpm、deb、pip、npm、jar、go-binary、go-module、binary 等
	Vendor       string `gorm:"column:vendor;type:varchar(255)" json:"vendor"`
	InstallTime  string `gorm:"column:install_time;type:varchar(50)" json:"install_time"`
	PURL         string `gorm:"column:purl;type:varchar(500);index" json:"purl"`
	Ecosystem    string `gorm:"column:ecosystem;type:varchar(30);index" json:"ecosystem"` // 生态系统：OS / Go / npm / PyPI / Maven / Cargo
	SourceFile   string `gorm:"column:source_file;type:varchar(500)" json:"source_file"`  // 依赖文件来源路径
	// Scope 控制漏洞匹配维度（防误报核心字段）：
	//   system   = 主机/容器上独立运行的服务/二进制本体（CPE + PURL 双维度匹配）
	//   embedded = 静态链接进宿主 binary 的依赖库（仅 PURL 维度，跳过 CPE daemon 匹配）
	//   container = 容器内的包（独立命名空间）
	// 旧记录默认 system，新 collector (1.2.0+) 由 source_handler 填写。
	Scope string `gorm:"column:scope;type:varchar(16);default:system;index" json:"scope"`
	// SourceHandler 标识采集来源 handler（rpm/dpkg/binary_probe/jar_scanner/go_buildinfo/python/node/container_sbom）。
	SourceHandler string `gorm:"column:source_handler;type:varchar(32);index" json:"source_handler"`
	// HostBinaryPath 仅 scope=embedded 有效：宿主 binary 路径（用于排查依赖来源）。
	HostBinaryPath string    `gorm:"column:host_binary_path;type:varchar(500)" json:"host_binary_path"`
	CollectedAt    LocalTime `gorm:"column:collected_at;type:timestamp;not null;index" json:"collected_at"`
}

// TableName 指定表名
func (Software) TableName() string {
	return "software"
}
