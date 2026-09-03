package cluster

import "testing"

func TestNodesWithRole(t *testing.T) {
	c := &Config{Nodes: []Node{
		{Name: "n1", Host: "10.0.0.1", Roles: []string{"control"}},
		{Name: "n2", Host: "10.0.0.2", Roles: []string{"agentcenter"}},
		{Name: "n3", Host: "10.0.0.3", Roles: []string{"agentcenter"}},
		{Name: "n5", Host: "10.0.0.5", Roles: []string{"storage"}},
	}}
	ac := c.NodesWithRole(RoleAgentCenter)
	if len(ac) != 3 {
		t.Fatalf("agentcenter nodes=%d want 3 (n1 via control alias + n2 + n3)", len(ac))
	}
	my := c.NodesWithRole(RoleMySQL)
	if len(my) != 1 || my[0].Name != "n5" {
		t.Fatalf("mysql node = %+v", my)
	}
}
