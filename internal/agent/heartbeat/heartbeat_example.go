// Package heartbeat 提供心跳上报功能
// 本文件展示如何在心跳采集时添加磁盘和网卡信息
//
// 使用示例：
// 在心跳采集函数中调用 CollectDiskInfo 和 CollectNetworkInterfaces，
// 然后将结果添加到心跳数据的 fields map 中。
package heartbeat

import (
	"context"
	"time"

	"go.uber.org/zap"

	bridgeProto "github.com/imkerbos/mxsec-platform/api/proto/bridge"
)

// SendHeartbeatExample 心跳上报示例函数
// 展示如何在心跳中添加磁盘和网卡信息
func SendHeartbeatExample(ctx context.Context, logger *zap.Logger, agentID string) (*bridgeProto.Record, error) {
	// 创建心跳数据的 fields map
	fields := make(map[string]string)

	// ... 采集其他主机信息（OS、硬件、网络基础信息等）...
	// fields["os_family"] = getOSFamily()
	// fields["kernel_version"] = getKernelVersion()
	// fields["cpu_info"] = getCPUInfo()
	// fields["memory_size"] = getMemorySize()
	// ... 等等 ...

	// 采集磁盘信息
	diskInfoJSON := CollectDiskInfo(ctx, logger)
	if diskInfoJSON != "" {
		fields["disk_info"] = diskInfoJSON
		logger.Debug("disk info collected", zap.String("disk_info", diskInfoJSON))
	} else {
		logger.Debug("disk info collection failed or no disks found")
	}

	// 采集网卡信息
	networkInterfacesJSON := CollectNetworkInterfaces(ctx, logger)
	if networkInterfacesJSON != "" {
		fields["network_interfaces"] = networkInterfacesJSON
		logger.Debug("network interfaces collected", zap.String("network_interfaces", networkInterfacesJSON))
	} else {
		logger.Debug("network interfaces collection failed or no interfaces found")
	}

	// 构建 bridge.Record
	record := &bridgeProto.Record{
		DataType:  1000, // 心跳数据类型
		Timestamp: time.Now().UnixNano(),
		Data: &bridgeProto.Payload{
			Fields: fields,
		},
	}

	return record, nil
}

// 注意：
// 1. CollectDiskInfo 和 CollectNetworkInterfaces 函数在采集失败时返回空字符串，
//    不会返回错误，避免影响心跳的正常上报
// 2. 磁盘信息采集使用 df 命令，可能有一定延迟，建议使用 context 控制超时
// 3. 网卡信息采集使用 net.Interfaces()，通常很快，但也要注意 context 取消
// 4. 如果采集失败或没有数据，对应的字段不会被添加到 fields map 中，
//    Server 端会保持原有值不变
