package celengine

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// processRetainDuration 进程退出后保留时间（用于延迟事件关联）
	processRetainDuration = 2 * time.Hour

	// processTreeCleanupInterval 清理过期进程的间隔
	processTreeCleanupInterval = 10 * time.Minute

	// maxAncestorDepth ancestor_has 查询最大回溯深度
	maxAncestorDepth = 32
)

// ProcessNode 进程树节点
type ProcessNode struct {
	PID       string
	PPID      string
	Exe       string
	Cmdline   string
	UID       string
	StartTime time.Time
	ExitTime  *time.Time // nil = still running

	parent   *ProcessNode
	children []*ProcessNode
}

// ProcessTree 按主机维护的进程树
// 键: hostID → pid → ProcessNode
type ProcessTree struct {
	mu     sync.RWMutex
	hosts  map[string]map[string]*ProcessNode // hostID → pid → node
	logger *zap.Logger
}

// NewProcessTree 创建进程树
func NewProcessTree(logger *zap.Logger) *ProcessTree {
	return &ProcessTree{
		hosts:  make(map[string]map[string]*ProcessNode),
		logger: logger,
	}
}

// HandleExec 处理 process_exec 事件，将新进程加入树
func (t *ProcessTree) HandleExec(hostID string, fields map[string]string) {
	pid := fields["pid"]
	ppid := fields["ppid"]
	if pid == "" {
		return
	}

	node := &ProcessNode{
		PID:       pid,
		PPID:      ppid,
		Exe:       fields["exe"],
		Cmdline:   fields["cmdline"],
		UID:       fields["uid"],
		StartTime: time.Now(),
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	hostTree := t.hosts[hostID]
	if hostTree == nil {
		hostTree = make(map[string]*ProcessNode)
		t.hosts[hostID] = hostTree
	}

	// Link to parent if exists.
	if ppid != "" {
		if parent, ok := hostTree[ppid]; ok {
			node.parent = parent
			parent.children = append(parent.children, node)
		}
	}

	hostTree[pid] = node
}

// HandleExit 处理 process_exit 事件，标记进程退出时间
func (t *ProcessTree) HandleExit(hostID string, fields map[string]string) {
	pid := fields["pid"]
	if pid == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	hostTree := t.hosts[hostID]
	if hostTree == nil {
		return
	}

	if node, ok := hostTree[pid]; ok {
		now := time.Now()
		node.ExitTime = &now
	}
}

// AncestorHas 检查指定主机上的进程祖先链中是否有匹配 exe 的进程
// 用于 CEL 自定义函数 ancestor_has(exe_pattern)
func (t *ProcessTree) AncestorHas(hostID, pid, exePattern string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hostTree := t.hosts[hostID]
	if hostTree == nil {
		return false
	}

	node, ok := hostTree[pid]
	if !ok {
		return false
	}

	// Walk up the parent chain.
	current := node.parent
	for depth := 0; current != nil && depth < maxAncestorDepth; depth++ {
		if containsPattern(current.Exe, exePattern) {
			return true
		}
		current = current.parent
	}

	return false
}

// GetAncestorChain 返回进程的祖先链 exe 列表（从近到远）
func (t *ProcessTree) GetAncestorChain(hostID, pid string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hostTree := t.hosts[hostID]
	if hostTree == nil {
		return nil
	}

	node, ok := hostTree[pid]
	if !ok {
		return nil
	}

	var chain []string
	current := node.parent
	for depth := 0; current != nil && depth < maxAncestorDepth; depth++ {
		chain = append(chain, current.Exe)
		current = current.parent
	}

	return chain
}

// Cleanup 清理过期进程节点（已退出且超过保留时间的）
func (t *ProcessTree) Cleanup() int {
	cutoff := time.Now().Add(-processRetainDuration)

	t.mu.Lock()
	defer t.mu.Unlock()

	var removed int
	for hostID, hostTree := range t.hosts {
		for pid, node := range hostTree {
			if node.ExitTime != nil && node.ExitTime.Before(cutoff) {
				// Unlink from parent.
				if node.parent != nil {
					siblings := node.parent.children
					for i, c := range siblings {
						if c == node {
							node.parent.children = append(siblings[:i], siblings[i+1:]...)
							break
						}
					}
				}
				// Re-parent children to grandparent.
				for _, child := range node.children {
					child.parent = node.parent
					if node.parent != nil {
						node.parent.children = append(node.parent.children, child)
					}
				}
				delete(hostTree, pid)
				removed++
			}
		}
		// Remove empty host trees.
		if len(hostTree) == 0 {
			delete(t.hosts, hostID)
		}
	}

	if removed > 0 {
		t.logger.Debug("进程树清理", zap.Int("removed", removed))
	}

	return removed
}

// Stats 返回进程树统计
func (t *ProcessTree) Stats() (hosts int, totalNodes int) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	hosts = len(t.hosts)
	for _, hostTree := range t.hosts {
		totalNodes += len(hostTree)
	}
	return
}

// containsPattern 简单模式匹配（包含检查）
func containsPattern(exe, pattern string) bool {
	if pattern == "" {
		return false
	}
	return exe == pattern || len(exe) > 0 && len(pattern) > 0 && contains(exe, pattern)
}

// contains is a simple substring check (avoid importing strings for this one use).
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
