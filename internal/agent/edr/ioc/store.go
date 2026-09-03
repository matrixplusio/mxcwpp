//go:build linux

// Package ioc provides an in-memory IOC (Indicator of Compromise) store
// for the EDR engine. It receives IOC data from the AgentCenter via gRPC
// Task messages and supports both full loads and incremental diff updates.
package ioc

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// iocData is the JSON structure matching the server-side IOC snapshot format.
type iocData struct {
	IP   []string `json:"ip"`
	Hash []string `json:"hash"`
	URL  []string `json:"url"`
}

// fullMessage is the JSON envelope for a full IOC push: {"type":"full","data":{...}}
type fullMessage struct {
	Type string  `json:"type"`
	Data iocData `json:"data"`
}

// diffMessage is the JSON envelope for an incremental IOC push:
// {"type":"diff","added":{...},"removed":{...}}
type diffMessage struct {
	Type    string  `json:"type"`
	Added   iocData `json:"added"`
	Removed iocData `json:"removed"`
}

// Store holds IOC indicators in hash maps for O(1) lookup.
// Thread-safe for concurrent reads (event pipeline) and writes (task receiver).
type Store struct {
	mu      sync.RWMutex
	version string
	ips     map[string]struct{}
	hashes  map[string]struct{}
	urls    map[string]struct{}
	count   atomic.Int64
	logger  *zap.Logger
}

// NewStore creates an empty IOC store.
func NewStore(logger *zap.Logger) *Store {
	return &Store{
		ips:    make(map[string]struct{}),
		hashes: make(map[string]struct{}),
		urls:   make(map[string]struct{}),
		logger: logger,
	}
}

// Load parses an IOC Task payload (JSON string) and updates the store.
// It auto-detects the message type ("full" or "diff") from the JSON.
func (s *Store) Load(data string) error {
	if data == "" {
		return fmt.Errorf("empty IOC data")
	}

	// Peek at "type" field to determine message format.
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(data), &envelope); err != nil {
		return fmt.Errorf("failed to parse IOC envelope: %w", err)
	}

	switch envelope.Type {
	case "full":
		return s.loadFull(data)
	case "diff":
		return s.applyDiff(data)
	default:
		return fmt.Errorf("unknown IOC message type: %q", envelope.Type)
	}
}

// loadFull replaces the entire store with a full IOC dataset.
func (s *Store) loadFull(data string) error {
	var msg fullMessage
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return fmt.Errorf("failed to parse full IOC message: %w", err)
	}

	ips := make(map[string]struct{}, len(msg.Data.IP))
	for _, v := range msg.Data.IP {
		ips[v] = struct{}{}
	}

	hashes := make(map[string]struct{}, len(msg.Data.Hash))
	for _, v := range msg.Data.Hash {
		hashes[v] = struct{}{}
	}

	urls := make(map[string]struct{}, len(msg.Data.URL))
	for _, v := range msg.Data.URL {
		urls[v] = struct{}{}
	}

	total := len(ips) + len(hashes) + len(urls)

	s.mu.Lock()
	s.ips = ips
	s.hashes = hashes
	s.urls = urls
	s.mu.Unlock()

	s.count.Store(int64(total))

	s.logger.Info("IOC store loaded (full)",
		zap.Int("ips", len(ips)),
		zap.Int("hashes", len(hashes)),
		zap.Int("urls", len(urls)),
	)
	return nil
}

// applyDiff applies an incremental diff to the store (add/remove entries).
func (s *Store) applyDiff(data string) error {
	var msg diffMessage
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return fmt.Errorf("failed to parse diff IOC message: %w", err)
	}

	s.mu.Lock()

	// Apply additions.
	for _, v := range msg.Added.IP {
		s.ips[v] = struct{}{}
	}
	for _, v := range msg.Added.Hash {
		s.hashes[v] = struct{}{}
	}
	for _, v := range msg.Added.URL {
		s.urls[v] = struct{}{}
	}

	// Apply removals.
	for _, v := range msg.Removed.IP {
		delete(s.ips, v)
	}
	for _, v := range msg.Removed.Hash {
		delete(s.hashes, v)
	}
	for _, v := range msg.Removed.URL {
		delete(s.urls, v)
	}

	total := len(s.ips) + len(s.hashes) + len(s.urls)
	s.mu.Unlock()

	s.count.Store(int64(total))

	added := len(msg.Added.IP) + len(msg.Added.Hash) + len(msg.Added.URL)
	removed := len(msg.Removed.IP) + len(msg.Removed.Hash) + len(msg.Removed.URL)
	s.logger.Info("IOC store updated (diff)",
		zap.Int("added", added),
		zap.Int("removed", removed),
		zap.Int("total", total),
	)
	return nil
}

// CheckIP returns true if the IP address is a known IOC.
func (s *Store) CheckIP(ip string) bool {
	s.mu.RLock()
	_, ok := s.ips[ip]
	s.mu.RUnlock()
	return ok
}

// CheckHash returns true if the hash is a known IOC.
func (s *Store) CheckHash(hash string) bool {
	s.mu.RLock()
	_, ok := s.hashes[hash]
	s.mu.RUnlock()
	return ok
}

// CheckURL returns true if the URL is a known IOC.
func (s *Store) CheckURL(url string) bool {
	s.mu.RLock()
	_, ok := s.urls[url]
	s.mu.RUnlock()
	return ok
}

// Version returns the current IOC version string.
func (s *Store) Version() string {
	s.mu.RLock()
	v := s.version
	s.mu.RUnlock()
	return v
}

// SetVersion sets the IOC version (called after successful Load).
func (s *Store) SetVersion(v string) {
	s.mu.Lock()
	s.version = v
	s.mu.Unlock()
}

// Count returns the total number of IOC entries across all types.
func (s *Store) Count() int {
	return int(s.count.Load())
}

// Stats returns counts per IOC type.
func (s *Store) Stats() (ips, hashes, urls int) {
	s.mu.RLock()
	ips = len(s.ips)
	hashes = len(s.hashes)
	urls = len(s.urls)
	s.mu.RUnlock()
	return
}
