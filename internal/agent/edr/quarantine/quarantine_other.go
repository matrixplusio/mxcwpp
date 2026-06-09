//go:build !linux

package quarantine

import (
	"errors"

	"go.uber.org/zap"
)

type Manager struct{}
type Metadata struct {
	QID, OriginalPath, SHA256, TriggerRule, TriggerSource string
}

func NewManager(_ string, _ *zap.Logger) (*Manager, error) {
	return nil, errors.New("quarantine: linux only")
}

func (m *Manager) Quarantine(_, _, _ string) (*Metadata, error) {
	return nil, errors.New("quarantine: linux only")
}
func (m *Manager) Restore(_ string) (*Metadata, error) { return nil, errors.New("linux only") }
func (m *Manager) Delete(_ string) error               { return errors.New("linux only") }
func (m *Manager) List() ([]*Metadata, error)          { return nil, errors.New("linux only") }
