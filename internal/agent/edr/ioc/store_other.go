//go:build !linux

package ioc

import "go.uber.org/zap"

// Store is a no-op stub on non-Linux platforms.
type Store struct{}

// NewStore returns a no-op store on non-Linux platforms.
func NewStore(_ *zap.Logger) *Store { return &Store{} }

// Load is a no-op stub.
func (s *Store) Load(_ string) error { return nil }

// CheckIP always returns false on non-Linux platforms.
func (s *Store) CheckIP(_ string) bool { return false }

// CheckHash always returns false on non-Linux platforms.
func (s *Store) CheckHash(_ string) bool { return false }

// CheckURL always returns false on non-Linux platforms.
func (s *Store) CheckURL(_ string) bool { return false }

// Version returns empty string on non-Linux platforms.
func (s *Store) Version() string { return "" }

// SetVersion is a no-op stub.
func (s *Store) SetVersion(_ string) {}

// Count returns 0 on non-Linux platforms.
func (s *Store) Count() int { return 0 }

// Stats returns zeroes on non-Linux platforms.
func (s *Store) Stats() (ips, hashes, urls int) { return 0, 0, 0 }
