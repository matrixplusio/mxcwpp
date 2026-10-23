// Package agentident 是 agent 与 AgentCenter 之间关于「这台机器是谁」的约定。
//
// AgentID 由 agent 本地派生，克隆出来的机器（系统模板、云镜像、预装 agent 的镜像）
// 会派生出同一个 ID。本地没法判断自己是不是克隆，所以由服务端比对机器指纹兜底：
// 同一个 AgentID 出现在指纹不同的机器上，就是身份冲突。
//
// 写入与读取放在同一个包里：两侧一旦各写一份 key，漂移只会表现为「检测从不触发」，
// 两边各自的单测都发现不了。
package agentident

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// FingerprintMetaKey 是 agent 经 gRPC metadata 上报机器指纹的 key。
const FingerprintMetaKey = "x-machine-fingerprint"

// conflictMarker 写在冲突状态的消息里，agent 据此区分「身份冲突」与其它 AlreadyExists。
const conflictMarker = "agent-identity-conflict"

// WithFingerprint 把机器指纹挂到出站 metadata。指纹为空时原样返回：服务端视为未知，不做比对。
func WithFingerprint(ctx context.Context, fingerprint string) context.Context {
	if fingerprint == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, FingerprintMetaKey, fingerprint)
}

// FingerprintFromIncoming 读取入站 metadata 里的机器指纹，没有时返回空串。
func FingerprintFromIncoming(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if v := md.Get(FingerprintMetaKey); len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

// ConflictError 构造服务端拒绝连接时返回的身份冲突状态。
func ConflictError(detail string) error {
	return status.Errorf(codes.AlreadyExists, "%s: %s", conflictMarker, detail)
}

// IsConflict 判断 agent 收到的错误是否为身份冲突。
func IsConflict(err error) bool {
	if err == nil {
		return false
	}
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		return false
	}
	st := se.GRPCStatus()
	return st.Code() == codes.AlreadyExists && strings.Contains(st.Message(), conflictMarker)
}
