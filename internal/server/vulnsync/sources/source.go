// Package sources 定义 VulnSync 漏洞情报数据源 Driver 抽象与具体实现。
//
// 11+ 数据源 (后续 PR 逐步加入):
//   - NVD (NIST) JSON 2.0 API
//   - OSV (Google)
//   - RedHat RHSA
//   - Ubuntu USN
//   - Debian DSA / Tracker
//   - Alpine SecDB
//   - SUSE
//   - CISA KEV
//   - ExploitDB
//   - CNNVD (编号补全)
//   - openEuler CSA RSS / Anolis ANSA / Kylin KYSA / UOS UOSEC (信创)
//   - EPSS (FIRST.org)
//
// 设计文档: docs/vulnsync-design.md
package sources

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Advisory 是单条漏洞情报记录 (内部统一 schema)。
//
// 各 Driver 把原始数据归一化成 Advisory,VulnSync 仲裁后推送到 Kafka mxsec.vuln.advisory。
type Advisory struct {
	Source        string    `json:"source"`    // nvd / osv / rhsa / usn / debian / alpine / suse / kev / exploitdb / cnnvd / openeuler / anolis / kylin / uos / epss
	SourceID      string    `json:"source_id"` // 源内唯一 ID,如 CVE-2024-1234 / RHSA-2024:0001
	CVE           string    `json:"cve"`       // CVE 编号 (空时为 source-only)
	CNNVD         string    `json:"cnnvd,omitempty"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	Severity      string    `json:"severity"` // critical / high / medium / low / unknown
	CVSSv3Vector  string    `json:"cvss_v3_vector,omitempty"`
	CVSSv3Score   float64   `json:"cvss_v3_score,omitempty"`
	CVSSv4Vector  string    `json:"cvss_v4_vector,omitempty"`
	CVSSv4Score   float64   `json:"cvss_v4_score,omitempty"`
	EPSSScore     float64   `json:"epss_score,omitempty"`
	KEVKnown      bool      `json:"kev_known,omitempty"`
	AffectedPURLs []string  `json:"affected_purls,omitempty"` // OSV 风格
	AffectedNEVRA []string  `json:"affected_nevra,omitempty"` // RPM 风格
	FixedVersions []string  `json:"fixed_versions,omitempty"`
	PublishedAt   time.Time `json:"published_at"`
	ModifiedAt    time.Time `json:"modified_at"`
	URL           string    `json:"url"`
	Raw           []byte    `json:"-"` // 原始响应保留,不入 JSON
}

// FetchResult 一次抓取的产物。
type FetchResult struct {
	Source     string
	Advisories []Advisory
	Errors     []error // 部分失败时记录单条错误
	FetchedAt  time.Time
}

// Driver 是数据源抽象。
//
// 每种数据源在子文件实现 Driver, 启动时注册到 Registry。
type Driver interface {
	// Name 返回数据源唯一名 (与配置 sources.<name>.enabled 一致)。
	Name() string

	// Fetch 增量/全量抓取最新 advisory。
	//
	// since 为上次成功 fetch 的时间, 零值视为全量。
	// 实现方应支持 ctx 取消, 避免长时间阻塞。
	Fetch(ctx context.Context, since time.Time) (*FetchResult, error)

	// HealthCheck 探活 (启动时校验配置/网络)。
	HealthCheck(ctx context.Context) error
}

// Registry 是 Driver 注册表。
type Registry struct {
	mu      sync.RWMutex
	drivers map[string]Driver
}

// NewRegistry 构造空 registry。
func NewRegistry() *Registry {
	return &Registry{drivers: make(map[string]Driver)}
}

// Register 注册 driver。
func (r *Registry) Register(d Driver) error {
	if d == nil {
		return fmt.Errorf("sources: driver must not be nil")
	}
	name := d.Name()
	if name == "" {
		return fmt.Errorf("sources: Name() must not be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.drivers[name]; ok {
		return fmt.Errorf("sources: %q already registered", name)
	}
	r.drivers[name] = d
	return nil
}

// Get 取 driver。
func (r *Registry) Get(name string) (Driver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.drivers[name]
	return d, ok
}

// Names 列出所有 driver 名。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.drivers))
	for n := range r.drivers {
		out = append(out, n)
	}
	return out
}
