package cluster

import (
	"strings"
	"testing"
)

// TestDispatchPredicates verifies that deploy.go dispatch and health-check gating
// use the expanded service set, not literal coarse-role strings.
func TestDispatchPredicates(t *testing.T) {
	type nodeCase struct {
		name           string
		roles          []string
		wantKafkaUp    bool
		wantStorageUp  bool
		wantControlUp  bool // control.yml started (hasAnyAppRole)
		wantCurlHealth bool // curl /health gated on manager or UI
	}

	cases := []nodeCase{
		// Fine-grained HA node with only agentcenter — the bug case.
		{
			name:           "agentcenter-only",
			roles:          []string{RoleAgentCenter},
			wantKafkaUp:    false,
			wantStorageUp:  false,
			wantControlUp:  true,  // has app role → control.yml must start
			wantCurlHealth: false, // no manager/UI → skip curl
		},
		// Fine-grained manager-only node.
		{
			name:           "manager-only",
			roles:          []string{RoleManager},
			wantKafkaUp:    false,
			wantStorageUp:  false,
			wantControlUp:  true,
			wantCurlHealth: true, // manager serves /health
		},
		// Coarse "control" alias — backward compat: expands to all 7 app roles.
		{
			name:           "control-legacy",
			roles:          []string{RoleControl},
			wantKafkaUp:    false,
			wantStorageUp:  false,
			wantControlUp:  true,
			wantCurlHealth: true, // has manager AND ui
		},
		// Coarse "storage" alias.
		{
			name:           "storage-legacy",
			roles:          []string{RoleStorage},
			wantKafkaUp:    false,
			wantStorageUp:  true,
			wantControlUp:  false,
			wantCurlHealth: false,
		},
		// Coarse "kafka" alias.
		{
			name:           "kafka-legacy",
			roles:          []string{RoleKafka},
			wantKafkaUp:    true,
			wantStorageUp:  false,
			wantControlUp:  false,
			wantCurlHealth: false,
		},
		// ui-only node.
		{
			name:           "ui-only",
			roles:          []string{RoleUI},
			wantKafkaUp:    false,
			wantStorageUp:  false,
			wantControlUp:  true,
			wantCurlHealth: true, // nginx /health on HTTPPort
		},
		// Fine-grained multi-role: consumer + engine (no manager, no ui).
		{
			name:           "consumer-engine",
			roles:          []string{RoleConsumer, RoleEngine},
			wantKafkaUp:    false,
			wantStorageUp:  false,
			wantControlUp:  true,
			wantCurlHealth: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := Node{Name: tc.name, Roles: tc.roles}
			svcSet := nodeServiceSet(node)

			if got := svcSet[RoleKafka]; got != tc.wantKafkaUp {
				t.Errorf("kafka dispatch: got %v, want %v", got, tc.wantKafkaUp)
			}
			if got := svcSet[RoleMySQL]; got != tc.wantStorageUp {
				t.Errorf("storage dispatch: got %v, want %v", got, tc.wantStorageUp)
			}
			if got := hasAnyAppRole(svcSet); got != tc.wantControlUp {
				t.Errorf("control dispatch: got %v, want %v", got, tc.wantControlUp)
			}
			if got := svcSet[RoleManager] || svcSet[RoleUI]; got != tc.wantCurlHealth {
				t.Errorf("curl /health gate: got %v, want %v", got, tc.wantCurlHealth)
			}
		})
	}
}

// TestRemoteHealthCheckScript verifies that remoteHealthCheck generates the correct
// command string for a fine-grained agentcenter-only node (no curl) and a legacy
// control node (with curl).
func TestRemoteHealthCheckScript(t *testing.T) {
	cfg := &Config{
		App: App{HTTPPort: 80},
	}

	t.Run("agentcenter-only-no-curl", func(t *testing.T) {
		node := deployedNode{
			Node:          Node{Name: "ac1", Roles: []string{RoleAgentCenter}, SSHUser: "root"},
			RemoteCurrent: "/opt/mxcwpp/current",
		}
		script := remoteHealthCheck(cfg, node)
		if strings.Contains(script, "curl") {
			t.Errorf("agentcenter-only node must not include curl /health, got: %s", script)
		}
		if !strings.Contains(script, "docker-compose.control.yml") {
			t.Errorf("agentcenter-only node must include docker compose ps for control.yml, got: %s", script)
		}
	})

	t.Run("control-legacy-has-curl", func(t *testing.T) {
		node := deployedNode{
			Node:          Node{Name: "ctrl1", Roles: []string{RoleControl}, SSHUser: "root"},
			RemoteCurrent: "/opt/mxcwpp/current",
		}
		script := remoteHealthCheck(cfg, node)
		if !strings.Contains(script, "curl") {
			t.Errorf("legacy control node must include curl /health, got: %s", script)
		}
		if !strings.Contains(script, "docker-compose.control.yml") {
			t.Errorf("legacy control node must include docker compose ps for control.yml, got: %s", script)
		}
	})
}
