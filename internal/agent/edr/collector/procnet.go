//go:build linux

package collector

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/edr/event"
)

// procNetPoller monitors network connections by polling /proc/net/{tcp,udp,tcp6,udp6}.
// New connections (absent in previous snapshot) emit network events.
// Known limitation: connections lasting < poll interval will be missed.
type procNetPoller struct {
	logger   *zap.Logger
	eventCh  chan<- *event.Event
	interval time.Duration

	// Previous snapshot for diff-based detection.
	prev map[connKey]struct{}
}

// connKey uniquely identifies a connection in /proc/net.
type connKey struct {
	protocol   string // "tcp" / "udp"
	localIP    string
	localPort  int
	remoteIP   string
	remotePort int
	inode      uint64
}

// parsedConn holds a parsed row from /proc/net/tcp or /proc/net/udp.
type parsedConn struct {
	connKey
	uid   int
	state int // TCP state; only ESTABLISHED (1) used for filtering
}

func newProcNetPoller(logger *zap.Logger, eventCh chan<- *event.Event, interval time.Duration) *procNetPoller {
	return &procNetPoller{
		logger:   logger,
		eventCh:  eventCh,
		interval: interval,
		prev:     make(map[connKey]struct{}),
	}
}

// pollLoop periodically snapshots /proc/net and emits events for new connections.
func (p *procNetPoller) pollLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// Take initial snapshot without emitting events.
	p.prev = p.snapshot()
	p.logger.Info("procnet poller initial snapshot", zap.Int("connections", len(p.prev)))

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.poll()
		}
	}
}

// poll takes a new snapshot, diffs against previous, and emits new connections.
func (p *procNetPoller) poll() {
	current := p.snapshot()

	for key := range current {
		if _, existed := p.prev[key]; existed {
			continue
		}
		// New connection detected.
		p.emitConnection(key)
	}

	p.prev = current
}

// emitConnection creates a network event from a connection key.
func (p *procNetPoller) emitConnection(key connKey) {
	var evtType event.EventType
	var protocol string

	switch key.protocol {
	case "tcp", "tcp6":
		evtType = event.TCPConnect
		protocol = "tcp"
	case "udp", "udp6":
		evtType = event.UDPSend
		protocol = "udp"
	default:
		return
	}

	// Skip loopback.
	if isLoopbackAddr(key.remoteIP) {
		return
	}

	evt := event.NewNetworkEvent(evtType, 0, key.remoteIP, key.remotePort, protocol)
	evt.SetField("source", "procnet")
	evt.SetField("local_addr", key.localIP)
	evt.SetField("local_port", fmt.Sprintf("%d", key.localPort))

	// DNS 事件标记：UDP 目标端口 53 标记为 DataType 3003
	if evtType == event.UDPSend && key.remotePort == 53 {
		evt.DataType = event.DataTypeDNS
		evt.EventType = event.DNSQuery
		evt.Fields["event_type"] = string(event.DNSQuery)
		evt.SetField("dns_server", key.remoteIP)
	}

	select {
	case p.eventCh <- evt:
	default:
	}
}

// snapshot reads all /proc/net files and returns the current connection set.
func (p *procNetPoller) snapshot() map[connKey]struct{} {
	result := make(map[connKey]struct{})

	files := []struct {
		path     string
		protocol string
		isV6     bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/tcp6", "tcp6", true},
		{"/proc/net/udp6", "udp6", true},
	}

	for _, f := range files {
		conns := p.parseFile(f.path, f.protocol, f.isV6)
		for _, c := range conns {
			// For TCP, only track ESTABLISHED connections (state 1).
			if (f.protocol == "tcp" || f.protocol == "tcp6") && c.state != 1 {
				continue
			}
			result[c.connKey] = struct{}{}
		}
	}

	return result
}

// parseFile reads and parses a /proc/net/{tcp,udp,tcp6,udp6} file.
func (p *procNetPoller) parseFile(path, protocol string, isV6 bool) []parsedConn {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var conns []parsedConn
	scanner := bufio.NewScanner(f)

	// Skip header line.
	if !scanner.Scan() {
		return nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		c, ok := parseProcNetLine(line, protocol, isV6)
		if ok {
			conns = append(conns, c)
		}
	}

	return conns
}

// parseProcNetLine parses a single line from /proc/net/{tcp,udp}.
// Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
func parseProcNetLine(line, protocol string, isV6 bool) (parsedConn, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return parsedConn{}, false
	}

	localIP, localPort, ok := parseAddr(fields[1], isV6)
	if !ok {
		return parsedConn{}, false
	}
	remoteIP, remotePort, ok := parseAddr(fields[2], isV6)
	if !ok {
		return parsedConn{}, false
	}

	state, _ := strconv.ParseInt(fields[3], 16, 32)
	uid, _ := strconv.Atoi(fields[7])
	inode, _ := strconv.ParseUint(fields[9], 10, 64)

	return parsedConn{
		connKey: connKey{
			protocol:   protocol,
			localIP:    localIP,
			localPort:  localPort,
			remoteIP:   remoteIP,
			remotePort: remotePort,
			inode:      inode,
		},
		uid:   uid,
		state: int(state),
	}, true
}

// parseAddr parses "AABBCCDD:PORT" (v4) or 32-hex-char ":PORT" (v6) from /proc/net.
func parseAddr(s string, isV6 bool) (string, int, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, false
	}

	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, false
	}

	ipStr := decodeIP(parts[0], isV6)
	return ipStr, int(port), ipStr != ""
}

// decodeIP decodes the hex-encoded IP from /proc/net.
// IPv4: 4 bytes little-endian. IPv6: 16 bytes in 4-byte groups little-endian.
func decodeIP(hexStr string, isV6 bool) string {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}

	if !isV6 {
		if len(b) != 4 {
			return ""
		}
		// /proc/net stores IPv4 in little-endian (reversed).
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}

	if len(b) != 16 {
		return ""
	}
	// /proc/net stores IPv6 as four 32-bit words, each in little-endian.
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		off := i * 4
		ip[off+0] = b[off+3]
		ip[off+1] = b[off+2]
		ip[off+2] = b[off+1]
		ip[off+3] = b[off+0]
	}
	return ip.String()
}

// isLoopbackAddr checks whether an IP string is a loopback address.
func isLoopbackAddr(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}
