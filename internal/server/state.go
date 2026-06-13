package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/HuJK/bridgedhcp/internal/pd"
)

// persistedIface is one interface's durable state: static bindings (API
// managed), active leases and the PD binding, so restarts neither
// renumber clients nor re-solicit a still-valid delegation.
type persistedIface struct {
	Statics4 []StaticBinding `json:"statics4,omitempty"`
	Statics6 []StaticBinding `json:"statics6,omitempty"`
	Leases4  []Lease         `json:"leases4,omitempty"`
	Leases6  []Lease         `json:"leases6,omitempty"`
	PD       *pd.Binding     `json:"pd,omitempty"`
}

type persistedState struct {
	Ifaces map[string]*persistedIface `json:"ifaces"`
}

// stateStore saves debounced snapshots atomically.
type stateStore struct {
	path string

	mu      sync.Mutex
	pending bool
	collect func() persistedState
}

func newStateStore(path string, collect func() persistedState) *stateStore {
	return &stateStore{path: path, collect: collect}
}

func (s *stateStore) load() (persistedState, error) {
	st := persistedState{Ifaces: map[string]*persistedIface{}}
	if s.path == "" {
		return st, nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return persistedState{Ifaces: map[string]*persistedIface{}}, err
	}
	if st.Ifaces == nil {
		st.Ifaces = map[string]*persistedIface{}
	}
	return st, nil
}

// markDirty schedules a save shortly; bursts coalesce.
func (s *stateStore) markDirty() {
	if s.path == "" {
		return
	}
	s.mu.Lock()
	if s.pending {
		s.mu.Unlock()
		return
	}
	s.pending = true
	s.mu.Unlock()
	time.AfterFunc(time.Second, func() {
		s.mu.Lock()
		s.pending = false
		s.mu.Unlock()
		s.saveNow()
	})
}

func (s *stateStore) saveNow() {
	if s.path == "" {
		return
	}
	st := s.collect()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
}
