// Package kube 提供 K8s/GKE 安全检查能力。
// 本文件实现 GKE 托管层专项基线：通过 GCP Container API 拉取集群配置，
// 对 CIS GKE Benchmark 关注的托管面控制项（Shielded Nodes / Workload Identity /
// 私有集群 / Binary Authorization / Release Channel / 节点自动升级等）做评估。
// 这些控制项不在 K8s API 内，必须读 GCP 侧配置，是区分通用 CIS 与商业级 GKE 加固的关键。
package kube

import (
	"context"
	"fmt"

	"google.golang.org/api/container/v1"
	"google.golang.org/api/option"
)

// GKE 专项检查项 CheckID（CIS GKE Benchmark 映射，与通用 CIS-K8S-* 区分）
const (
	GKEShieldedNodes     = "CIS-GKE-001"
	GKEWorkloadIdentity  = "CIS-GKE-002"
	GKEPrivateNodes      = "CIS-GKE-003"
	GKEBinaryAuth        = "CIS-GKE-004"
	GKEMasterAuthNets    = "CIS-GKE-005"
	GKEReleaseChannel    = "CIS-GKE-006"
	GKENodeAutoUpgrade   = "CIS-GKE-007"
	GKENodeAutoRepair    = "CIS-GKE-008"
	GKENetworkPolicy     = "CIS-GKE-009"
	GKELegacyABAC        = "CIS-GKE-010"
	GKEClientCertAuth    = "CIS-GKE-011"
	GKECloudLogging      = "CIS-GKE-012"
	GKESecretsEncryption = "CIS-GKE-013"
)

// GKECheckIDs 全部 GKE 专项检查 ID（供基线 checker 识别 + 结果合并）
var GKECheckIDs = []string{
	GKEShieldedNodes, GKEWorkloadIdentity, GKEPrivateNodes, GKEBinaryAuth,
	GKEMasterAuthNets, GKEReleaseChannel, GKENodeAutoUpgrade, GKENodeAutoRepair,
	GKENetworkPolicy, GKELegacyABAC, GKEClientCertAuth, GKECloudLogging,
	GKESecretsEncryption,
}

// FetchGKECluster 通过 GCP Container API 获取集群托管层配置。
// saJSON 为空时回退到 ADC（VM 默认服务账号）；要求凭证具备 container.clusters.get 权限。
func FetchGKECluster(ctx context.Context, projectID, location, clusterName, saJSON string) (*container.Cluster, error) {
	if projectID == "" || location == "" || clusterName == "" {
		return nil, fmt.Errorf("GKE 坐标不完整(project=%q location=%q cluster=%q)", projectID, location, clusterName)
	}
	var opts []option.ClientOption
	if saJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(saJSON))) //nolint:staticcheck // TODO: migrate to newer auth approach
	}
	svc, err := container.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("创建 Container API 客户端失败: %w", err)
	}
	name := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectID, location, clusterName)
	cl, err := svc.Projects.Locations.Clusters.Get(name).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("获取 GKE 集群配置失败: %w", err)
	}
	return cl, nil
}

// EvaluateGKEChecks 对 GKE 集群配置做托管层基线评估，返回 checkID -> "pass"/"fail"。
// 纯函数（无 IO），可单测。安全特性缺省/未启用一律判 fail（hardening 基线的安全默认）。
func EvaluateGKEChecks(cfg *container.Cluster) map[string]string {
	res := make(map[string]string, len(GKECheckIDs))
	verdict := func(id string, pass bool) {
		if pass {
			res[id] = "pass"
		} else {
			res[id] = "fail"
		}
	}

	verdict(GKEShieldedNodes, cfg.ShieldedNodes != nil && cfg.ShieldedNodes.Enabled)
	verdict(GKEWorkloadIdentity, cfg.WorkloadIdentityConfig != nil && cfg.WorkloadIdentityConfig.WorkloadPool != "")
	verdict(GKEPrivateNodes, cfg.PrivateClusterConfig != nil && cfg.PrivateClusterConfig.EnablePrivateNodes)
	verdict(GKEBinaryAuth, binaryAuthEnabled(cfg.BinaryAuthorization))
	verdict(GKEMasterAuthNets, cfg.MasterAuthorizedNetworksConfig != nil && cfg.MasterAuthorizedNetworksConfig.Enabled)
	verdict(GKEReleaseChannel, releaseChannelRegistered(cfg.ReleaseChannel))
	verdict(GKENodeAutoUpgrade, allNodePools(cfg, func(m *container.NodeManagement) bool { return m != nil && m.AutoUpgrade }))
	verdict(GKENodeAutoRepair, allNodePools(cfg, func(m *container.NodeManagement) bool { return m != nil && m.AutoRepair }))
	verdict(GKENetworkPolicy, networkPolicyEnabled(cfg))
	verdict(GKELegacyABAC, cfg.LegacyAbac == nil || !cfg.LegacyAbac.Enabled)
	verdict(GKEClientCertAuth, cfg.MasterAuth == nil || cfg.MasterAuth.ClientCertificate == "")
	verdict(GKECloudLogging, cfg.LoggingService != "" && cfg.LoggingService != "none")
	verdict(GKESecretsEncryption, cfg.DatabaseEncryption != nil && cfg.DatabaseEncryption.State == "ENCRYPTED")

	return res
}

func binaryAuthEnabled(ba *container.BinaryAuthorization) bool {
	if ba == nil {
		return false
	}
	if ba.Enabled {
		return true
	}
	switch ba.EvaluationMode {
	case "", "DISABLED", "EVALUATION_MODE_UNSPECIFIED":
		return false
	default:
		return true
	}
}

func releaseChannelRegistered(rc *container.ReleaseChannel) bool {
	if rc == nil {
		return false
	}
	switch rc.Channel {
	case "", "UNSPECIFIED":
		return false
	default:
		return true
	}
}

// networkPolicyEnabled：NetworkPolicy addon 启用，或使用 Dataplane V2（ADVANCED_DATAPATH，原生网络策略）
func networkPolicyEnabled(cfg *container.Cluster) bool {
	if cfg.NetworkPolicy != nil && cfg.NetworkPolicy.Enabled {
		return true
	}
	if cfg.NetworkConfig != nil && cfg.NetworkConfig.DatapathProvider == "ADVANCED_DATAPATH" {
		return true
	}
	return false
}

// allNodePools：所有节点池都满足 pred 才算 pass（无节点池视为 fail）
func allNodePools(cfg *container.Cluster, pred func(*container.NodeManagement) bool) bool {
	if len(cfg.NodePools) == 0 {
		return false
	}
	for _, np := range cfg.NodePools {
		if np == nil || !pred(np.Management) {
			return false
		}
	}
	return true
}
