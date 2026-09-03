package canary

import (
	"context"
	"errors"
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

type fakeDriver struct {
	t            model.RolloutType
	pushed       int
	failed       int
	pushErr      error
	failureRate  float64
	readyAdvance bool
	rollbackErr  error
}

func (f *fakeDriver) Type() model.RolloutType { return f.t }

func (f *fakeDriver) Push(_ context.Context, _ *model.CanaryRollout, agents []string) (int, int, error) {
	if f.pushErr != nil {
		return 0, len(agents), f.pushErr
	}
	return f.pushed, f.failed, nil
}

func (f *fakeDriver) HealthCheck(_ context.Context, _ *model.CanaryRollout) (float64, bool, error) {
	return f.failureRate, f.readyAdvance, nil
}

func (f *fakeDriver) Rollback(_ context.Context, _ *model.CanaryRollout, _ string) error {
	return f.rollbackErr
}

func TestRegistry_Register_Lookup(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	d := &fakeDriver{t: model.RolloutTypeBaseline, pushed: 10, readyAdvance: true}

	if err := r.Register(d); err != nil {
		t.Fatalf("register: %v", err)
	}

	got, ok := r.Lookup(model.RolloutTypeBaseline)
	if !ok {
		t.Fatalf("lookup miss")
	}
	if got.Type() != model.RolloutTypeBaseline {
		t.Fatalf("expected baseline_fix, got %s", got.Type())
	}
}

func TestRegistry_RejectNil(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if err := r.Register(nil); err == nil {
		t.Fatalf("expected error for nil driver")
	}
}

func TestRegistry_RejectEmptyType(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if err := r.Register(&fakeDriver{t: ""}); err == nil {
		t.Fatalf("expected error for empty type")
	}
}

func TestRegistry_RejectDuplicate(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	d := &fakeDriver{t: model.RolloutTypeVulnFix}
	if err := r.Register(d); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := r.Register(d); err == nil {
		t.Fatalf("duplicate register should error")
	}
}

func TestRegistry_LookupMiss(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_, ok := r.Lookup(model.RolloutTypeAntivirus)
	if ok {
		t.Fatalf("expected miss for unregistered type")
	}
}

func TestRegistry_Types(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_ = r.Register(&fakeDriver{t: model.RolloutTypeBaseline})
	_ = r.Register(&fakeDriver{t: model.RolloutTypeVulnFix})

	got := r.Types()
	if len(got) != 2 {
		t.Fatalf("expected 2 types, got %d", len(got))
	}
}

func TestRegistry_MustRegister_PanicOnDuplicate(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on duplicate MustRegister")
		}
	}()
	r := NewRegistry()
	r.MustRegister(&fakeDriver{t: model.RolloutTypeConfig})
	r.MustRegister(&fakeDriver{t: model.RolloutTypeConfig}) // panic
}

func TestDefaultRegistry_Isolated(t *testing.T) {
	t.Parallel()
	// 不直接污染全局 DefaultRegistry: 这里只断言它存在且初始为空之外的类型可注册
	if DefaultRegistry == nil {
		t.Fatalf("DefaultRegistry must be non-nil")
	}
}

func TestDriver_PushErrorPropagates(t *testing.T) {
	t.Parallel()
	d := &fakeDriver{t: model.RolloutTypeRule, pushErr: errors.New("boom")}
	_, failed, err := d.Push(context.Background(), &model.CanaryRollout{}, []string{"a", "b"})
	if err == nil {
		t.Fatalf("expected push error")
	}
	if failed != 2 {
		t.Fatalf("expected 2 failed, got %d", failed)
	}
}
