// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/plugins/collector/engine"
)

// NetInterfaceHandler 是网络接口采集器
type NetInterfaceHandler struct {
	Logger *zap.Logger
}

// readProcNetDev 读取 /proc/net/dev，返回 interface_name -> [bytesRecv, packetsErr, packetsDrop, bytesSent]
func readProcNetDev() map[string][4]uint64 {
	stats := make(map[string][4]uint64)
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return stats
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// 跳过前两行标题
	scanner.Scan()
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			continue
		}
		bytesRecv, _ := strconv.ParseUint(fields[0], 10, 64)
		packetsErr, _ := strconv.ParseUint(fields[2], 10, 64)
		packetsDrop, _ := strconv.ParseUint(fields[3], 10, 64)
		bytesSent, _ := strconv.ParseUint(fields[8], 10, 64)
		stats[name] = [4]uint64{bytesRecv, packetsErr, packetsDrop, bytesSent}
	}
	return stats
}

// Collect 采集网络接口信息（含流量统计）
func (h *NetInterfaceHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var interfaces []interface{}

	// 一次性读取 /proc/net/dev 流量统计
	netDevStats := readProcNetDev()

	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		select {
		case <-ctx.Done():
			return interfaces, ctx.Err()
		default:
		}

		// 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 获取接口地址
		addrs, err := iface.Addrs()
		if err != nil {
			h.Logger.Debug("failed to get addresses for interface",
				zap.String("interface", iface.Name),
				zap.Error(err))
			continue
		}

		var ipv4Addrs []string
		var ipv6Addrs []string

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip.To4() != nil {
				ipv4Addrs = append(ipv4Addrs, ip.String())
			} else {
				ipv6Addrs = append(ipv6Addrs, ip.String())
			}
		}

		// 获取状态
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}

		netInterface := &engine.NetInterfaceAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			InterfaceName: iface.Name,
			MACAddress:    iface.HardwareAddr.String(),
			IPv4Addresses: ipv4Addrs,
			IPv6Addresses: ipv6Addrs,
			MTU:           iface.MTU,
			State:         state,
		}

		// 补充 /proc/net/dev 流量统计
		if s, ok := netDevStats[iface.Name]; ok {
			netInterface.BytesRecv = s[0]
			netInterface.PacketsError = s[1]
			netInterface.PacketsDrop = s[2]
			netInterface.BytesSent = s[3]
		}

		interfaces = append(interfaces, netInterface)
	}

	return interfaces, nil
}
