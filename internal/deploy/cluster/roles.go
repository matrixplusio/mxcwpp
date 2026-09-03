package cluster

import "fmt"

// Fine-grained service role constants.
const (
	RoleManager     = "manager"
	RoleAgentCenter = "agentcenter"
	RoleConsumer    = "consumer"
	RoleEngine      = "engine"
	RoleVulnSync    = "vulnsync"
	RoleLLMProxy    = "llmproxy"
	RoleUI          = "ui"
	RoleMySQL       = "mysql"
	RoleRedis       = "redis"
	RoleClickHouse  = "clickhouse"
	// RoleKafka is already defined in types.go ("kafka").
)

// canonicalOrder defines the deterministic output ordering for ExpandRoles.
var canonicalOrder = []string{
	RoleManager, RoleAgentCenter, RoleConsumer, RoleEngine,
	RoleVulnSync, RoleLLMProxy, RoleUI,
	RoleMySQL, RoleRedis, RoleClickHouse, RoleKafka,
}

// canonicalIndex maps each fine-grained role to its position in canonicalOrder.
var canonicalIndex = func() map[string]int {
	m := make(map[string]int, len(canonicalOrder))
	for i, r := range canonicalOrder {
		m[r] = i
	}
	return m
}()

// AppRoles returns the 7 application-layer roles (control-plane services).
func AppRoles() []string {
	return []string{RoleManager, RoleAgentCenter, RoleConsumer, RoleEngine, RoleVulnSync, RoleLLMProxy, RoleUI}
}

// InfraRoles returns the 4 infrastructure roles.
func InfraRoles() []string {
	return []string{RoleMySQL, RoleRedis, RoleClickHouse, RoleKafka}
}

// coarseAliases maps coarse-role aliases to their expanded fine-grained roles.
var coarseAliases = map[string][]string{
	RoleControl: AppRoles(),
	RoleStorage: {RoleMySQL, RoleRedis, RoleClickHouse},
	RoleKafka:   {RoleKafka},
}

// ExpandRoles expands coarse alias roles into fine-grained service roles,
// deduplicates, and returns them sorted by canonical service order.
// Returns an error if any role is unknown.
func ExpandRoles(roles []string) ([]string, error) {
	seen := make(map[string]struct{}, len(canonicalOrder))
	for _, r := range roles {
		if expanded, ok := coarseAliases[r]; ok {
			for _, e := range expanded {
				seen[e] = struct{}{}
			}
			continue
		}
		if _, ok := canonicalIndex[r]; ok {
			seen[r] = struct{}{}
			continue
		}
		return nil, fmt.Errorf("不支持的 role: %s", r)
	}

	out := make([]string, 0, len(seen))
	for _, r := range canonicalOrder {
		if _, ok := seen[r]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}
