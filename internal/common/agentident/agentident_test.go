package agentident

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// agent 写入与 AC 读取必须对得上：key 漂移只会表现为检测从不触发。
func TestFingerprintRoundTrip(t *testing.T) {
	out := WithFingerprint(context.Background(), "fp-1")
	md, _ := metadata.FromOutgoingContext(out)
	in := metadata.NewIncomingContext(context.Background(), md)
	if got := FingerprintFromIncoming(in); got != "fp-1" {
		t.Fatalf("got %q", got)
	}
	if got := FingerprintFromIncoming(context.Background()); got != "" {
		t.Fatalf("无 metadata 时应为空，got %q", got)
	}
	if _, ok := metadata.FromOutgoingContext(WithFingerprint(context.Background(), "")); ok {
		t.Fatal("空指纹不应写 metadata")
	}
}

// 只认身份冲突：别的 AlreadyExists 或普通错误被当成冲突，agent 会无故换掉身份。
func TestIsConflict(t *testing.T) {
	if !IsConflict(ConflictError("x")) {
		t.Fatal("ConflictError 应被识别")
	}
	if !IsConflict(fmt.Errorf("wrapped: %w", ConflictError("x"))) {
		t.Fatal("被包装后仍应识别")
	}
	for _, err := range []error{
		nil,
		errors.New("agent-identity-conflict"),
		status.Error(codes.AlreadyExists, "something else exists"),
		status.Error(codes.PermissionDenied, "agent-identity-conflict"),
	} {
		if IsConflict(err) {
			t.Errorf("不应识别为身份冲突: %v", err)
		}
	}
}
