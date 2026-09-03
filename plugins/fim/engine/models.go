// Package engine 提供 FIM 插件的核心引擎
package engine

// FIMPolicy 从任务 JSON 解析的策略配置
type FIMPolicy struct {
	PolicyID     string      `json:"policy_id"`
	WatchPaths   []WatchPath `json:"watch_paths"`
	ExcludePaths []string    `json:"exclude_paths"`
}

// WatchPath 监控路径配置
type WatchPath struct {
	Path    string `json:"path"`
	Level   string `json:"level"` // NORMAL, CONTENT, PERMS
	Comment string `json:"comment"`
}

// FileEntry 文件快照条目
type FileEntry struct {
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode,omitempty"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	MTime  int64  `json:"mtime"`
}

// FIMEvent 单个文件变更事件
type FIMEvent struct {
	EventID      string       `json:"event_id"`
	FilePath     string       `json:"file_path"`
	ChangeType   string       `json:"change_type"` // added, removed, changed
	Severity     string       `json:"severity"`    // critical, high, medium, low
	Category     string       `json:"category"`    // binary, auth, ssh, config, other
	ChangeDetail ChangeDetail `json:"change_detail"`
}

// ChangeDetail 变更详情
type ChangeDetail struct {
	SizeBefore        string `json:"size_before,omitempty"`
	SizeAfter         string `json:"size_after,omitempty"`
	HashBefore        string `json:"hash_before,omitempty"`
	HashAfter         string `json:"hash_after,omitempty"`
	ModeBefore        string `json:"mode_before,omitempty"`
	ModeAfter         string `json:"mode_after,omitempty"`
	Attributes        string `json:"attributes,omitempty"`
	HashChanged       bool   `json:"hash_changed"`
	PermissionChanged bool   `json:"permission_changed"`
	OwnerChanged      bool   `json:"owner_changed"`
}

// FIMSummary FIM 检查摘要
type FIMSummary struct {
	TotalEntries   int `json:"total_entries"`
	AddedEntries   int `json:"added_entries"`
	RemovedEntries int `json:"removed_entries"`
	ChangedEntries int `json:"changed_entries"`
}

// ExecuteResult 引擎执行结果
type ExecuteResult struct {
	PolicyID          string               `json:"policy_id,omitempty"`
	Summary           FIMSummary           `json:"summary"`
	Events            []FIMEvent           `json:"events"`
	IsInitialBaseline bool                 `json:"is_initial_baseline,omitempty"`
	Snapshot          map[string]FileEntry `json:"snapshot,omitempty"`
	Error             string               `json:"error,omitempty"`
}
