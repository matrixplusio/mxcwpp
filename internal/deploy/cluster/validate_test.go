package cluster

import "testing"

func baseHA() *Config {
	c := &Config{Nodes: []Node{
		{Name: "n1", Host: "10.0.0.1", Roles: []string{"manager", "ui", "engine", "consumer", "vulnsync", "llmproxy"}},
		{Name: "n2", Host: "10.0.0.2", Roles: []string{"agentcenter"}},
		{Name: "n3", Host: "10.0.0.3", Roles: []string{"agentcenter"}},
		{Name: "n5", Host: "10.0.0.5", Roles: []string{"mysql", "redis", "clickhouse"}},
		{Name: "n6", Host: "10.0.0.6", Roles: []string{"kafka"}},
	}}
	c.Metadata.Name = "test-cluster"
	c.Release.Version = "1.0.0"
	c.Network.UI.Host = "ui.example.com"
	c.Network.GRPC.Host = "grpc.example.com"
	c.App.JWTSecret = "test-jwt-secret"
	c.Infrastructure.MySQL.RootPassword = "root-pass"
	c.Infrastructure.MySQL.Password = "user-pass"
	c.Infrastructure.Kafka.BrokerPorts = []int{9092, 9094, 9095}
	return c
}

func TestValidateHAOK(t *testing.T) {
	if err := baseHA().Validate(); err != nil {
		t.Fatalf("HA config should pass: %v", err)
	}
}

func TestValidateMissingService(t *testing.T) {
	c := baseHA()
	c.Nodes = c.Nodes[1:] // 删掉含 manager 的 n1
	if err := c.Validate(); err == nil {
		t.Fatal("missing manager should fail")
	}
}

func TestValidateInfraMultiRejected(t *testing.T) {
	c := baseHA()
	c.Nodes = append(c.Nodes, Node{Name: "n7", Host: "10.0.0.7", Roles: []string{"mysql"}})
	if err := c.Validate(); err == nil {
		t.Fatal("2 mysql nodes should fail (singleton constraint)")
	}
}

func TestValidateBadRole(t *testing.T) {
	c := baseHA()
	c.Nodes[0].Roles = []string{"bogus"}
	if err := c.Validate(); err == nil {
		t.Fatal("bad role should fail")
	}
}

func TestValidateCoarseRolesStillOK(t *testing.T) {
	c := &Config{Nodes: []Node{
		{Name: "n1", Host: "10.0.0.1", Roles: []string{"control"}},
		{Name: "n2", Host: "10.0.0.2", Roles: []string{"storage"}},
		{Name: "n3", Host: "10.0.0.3", Roles: []string{"kafka"}},
	}}
	c.Metadata.Name = "test-cluster"
	c.Release.Version = "1.0.0"
	c.Network.UI.Host = "ui.example.com"
	c.Network.GRPC.Host = "grpc.example.com"
	c.App.JWTSecret = "test-jwt-secret"
	c.Infrastructure.MySQL.RootPassword = "root-pass"
	c.Infrastructure.MySQL.Password = "user-pass"
	c.Infrastructure.Kafka.BrokerPorts = []int{9092, 9094, 9095}
	if err := c.Validate(); err != nil {
		t.Fatalf("legacy coarse-role config must pass: %v", err)
	}
}
