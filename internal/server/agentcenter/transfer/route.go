package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"gorm.io/gorm/clause"

	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/common/internalauth"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 跨实例转发命令。
//
// 推送调度器（升级、重启、灰度）按库里的在线主机逐台发命令，而连接只在某一台 AC 上。
// 本机没有这条连接时，按 hosts.ac_instance 找到持有它的实例转过去；
// 只转一跳，对端只发本机连接，不会再转，避免环路。

const (
	instanceHeartbeat = 30 * time.Second
	// instanceAddrTTL 超过这么久没刷新的实例地址视为不可用。
	instanceAddrTTL = 2 * time.Minute
	forwardTimeout  = 5 * time.Second
)

// ErrAgentNotConnected agent 不在任何可达实例上。
var ErrAgentNotConnected = errors.New("agent 未连接")

// ForwardRequest 是 /command/raw 的请求体。
type ForwardRequest struct {
	AgentID string          `json:"agent_id"`
	Command json.RawMessage `json:"command"` // protojson 编码的 grpcProto.Command
}

// InstanceID 本实例 ID。
func (s *Service) InstanceID() string { return s.cfg.Server.InstanceID }

// Standby 是否为备用实例（不参与推送租约）。
func (s *Service) Standby() bool { return s.cfg.Server.Standby }

// StartInstanceHeartbeat 周期登记本实例的管理地址，ctx 取消时退出。
func (s *Service) StartInstanceHeartbeat(ctx context.Context, httpAddr string) {
	s.httpAddr = httpAddr
	s.registerInstance()
	t := time.NewTicker(instanceHeartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.registerInstance()
		}
	}
}

func (s *Service) registerInstance() {
	rec := model.ACInstanceRecord{
		InstanceID: s.cfg.Server.InstanceID,
		HTTPAddr:   s.httpAddr,
		UpdatedAt:  model.ToLocalTime(time.Now()),
	}
	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "instance_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"http_addr", "updated_at"}),
	}).Create(&rec).Error; err != nil {
		s.logger.Warn("登记 AC 实例地址失败", zap.Error(err))
	}
}

// RouteCommand 发命令给 agent：本机有连接直接发，否则转给持有连接的实例。
func (s *Service) RouteCommand(agentID string, cmd *grpcProto.Command) error {
	err := s.SendCommand(agentID, cmd)
	if err == nil || !strings.HasPrefix(err.Error(), "agent 未连接") {
		return err
	}
	var h model.Host
	if e := s.db.Select("ac_instance").Where("host_id = ?", agentID).First(&h).Error; e != nil ||
		h.ACInstance == "" || h.ACInstance == s.cfg.Server.InstanceID {
		return err
	}
	var peer model.ACInstanceRecord
	if e := s.db.Where("instance_id = ? AND updated_at >= ?", h.ACInstance,
		model.ToLocalTime(time.Now().Add(-instanceAddrTTL))).First(&peer).Error; e != nil {
		return fmt.Errorf("%w: 所在实例 %s 无可用地址", ErrAgentNotConnected, h.ACInstance)
	}
	return s.forward(peer, agentID, cmd)
}

func (s *Service) forward(peer model.ACInstanceRecord, agentID string, cmd *grpcProto.Command) error {
	if s.cfg.Server.ACAdminSecret == "" {
		// 带空密钥去调只会换来对端一个 401，看不出是本机没配
		return fmt.Errorf("未配置 server.ac_admin_secret，无法转发到实例 %s", peer.InstanceID)
	}
	raw, err := protojson.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("编码命令失败: %w", err)
	}
	body, _ := json.Marshal(ForwardRequest{AgentID: agentID, Command: raw})
	ctx, cancel := context.WithTimeout(context.Background(), forwardTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+peer.HTTPAddr+"/command/raw", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// 对端的 /command/raw 只认 ac_admin_secret（两台 AC 配置相同），不认 internal_secret。
	req.Header.Set(internalauth.HeaderName, s.cfg.Server.ACAdminSecret)
	resp, err := s.forwardClient.Do(req)
	if err != nil {
		return fmt.Errorf("转发到实例 %s 失败: %w", peer.InstanceID, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusServiceUnavailable:
		return fmt.Errorf("%w: %s（实例 %s）", ErrAgentNotConnected, agentID, peer.InstanceID)
	default:
		return fmt.Errorf("实例 %s 返回 %d", peer.InstanceID, resp.StatusCode)
	}
}

// DecodeForward 解出转发请求里的命令（供对端 HTTP 处理器用）。
func DecodeForward(r ForwardRequest) (*grpcProto.Command, error) {
	var cmd grpcProto.Command
	if err := protojson.Unmarshal(r.Command, &cmd); err != nil {
		return nil, err
	}
	return &cmd, nil
}
