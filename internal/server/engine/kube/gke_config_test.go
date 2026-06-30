package kube

import (
	"testing"

	"google.golang.org/api/container/v1"
)

// 全加固集群：除按语义应放行的项外，所有 GKE 专项检查应 pass
func TestEvaluateGKEChecks_Hardened(t *testing.T) {
	cfg := &container.Cluster{
		ShieldedNodes:                  &container.ShieldedNodes{Enabled: true},
		WorkloadIdentityConfig:         &container.WorkloadIdentityConfig{WorkloadPool: "proj.svc.id.goog"},
		PrivateClusterConfig:           &container.PrivateClusterConfig{EnablePrivateNodes: true},
		BinaryAuthorization:            &container.BinaryAuthorization{EvaluationMode: "PROJECT_SINGLETON_POLICY_ENFORCE"},
		MasterAuthorizedNetworksConfig: &container.MasterAuthorizedNetworksConfig{Enabled: true},
		ReleaseChannel:                 &container.ReleaseChannel{Channel: "REGULAR"},
		NetworkPolicy:                  &container.NetworkPolicy{Enabled: true},
		LegacyAbac:                     &container.LegacyAbac{Enabled: false},
		MasterAuth:                     &container.MasterAuth{ClientCertificate: ""},
		LoggingService:                 "logging.googleapis.com/kubernetes",
		DatabaseEncryption:             &container.DatabaseEncryption{State: "ENCRYPTED"},
		NodePools: []*container.NodePool{
			{Management: &container.NodeManagement{AutoUpgrade: true, AutoRepair: true}},
		},
	}
	got := EvaluateGKEChecks(cfg)
	for _, id := range GKECheckIDs {
		if got[id] != "pass" {
			t.Errorf("加固集群 %s 应 pass，实际 %q", id, got[id])
		}
	}
}

// 裸集群（安全特性全未启用）：除 LegacyABAC/客户端证书（nil 即合规）外都应 fail
func TestEvaluateGKEChecks_Bare(t *testing.T) {
	cfg := &container.Cluster{} // 全 nil/零值
	got := EvaluateGKEChecks(cfg)

	shouldPass := map[string]bool{
		GKELegacyABAC:     true, // LegacyAbac nil => 未启用 ABAC => 合规
		GKEClientCertAuth: true, // MasterAuth nil => 无客户端证书 => 合规
	}
	for _, id := range GKECheckIDs {
		want := "fail"
		if shouldPass[id] {
			want = "pass"
		}
		if got[id] != want {
			t.Errorf("裸集群 %s 期望 %q，实际 %q", id, want, got[id])
		}
	}
}

// Dataplane V2 应等价于网络策略启用
func TestEvaluateGKEChecks_DataplaneV2(t *testing.T) {
	cfg := &container.Cluster{
		NetworkConfig: &container.NetworkConfig{DatapathProvider: "ADVANCED_DATAPATH"},
	}
	if got := EvaluateGKEChecks(cfg); got[GKENetworkPolicy] != "pass" {
		t.Errorf("Dataplane V2 应使 %s pass，实际 %q", GKENetworkPolicy, got[GKENetworkPolicy])
	}
}

// 任一节点池未开自动升级 => 整体 fail
func TestEvaluateGKEChecks_PartialNodePool(t *testing.T) {
	cfg := &container.Cluster{
		NodePools: []*container.NodePool{
			{Management: &container.NodeManagement{AutoUpgrade: true}},
			{Management: &container.NodeManagement{AutoUpgrade: false}},
		},
	}
	if got := EvaluateGKEChecks(cfg); got[GKENodeAutoUpgrade] != "fail" {
		t.Errorf("存在未开自动升级的节点池时 %s 应 fail，实际 %q", GKENodeAutoUpgrade, got[GKENodeAutoUpgrade])
	}
}
