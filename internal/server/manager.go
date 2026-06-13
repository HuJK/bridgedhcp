package server

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/HuJK/bridgedhcp/internal/ifwatch"
)

// Manager owns every served interface plus the shared netlink watcher and
// state store. It is the backend of the control API.
type Manager struct {
	watcher *ifwatch.Watcher
	store   *stateStore
	ifaces  map[string]*Iface
	order   []string
}

// NewManager builds (but does not start) the served interfaces.
func NewManager(cfgs []IfaceConfig, stateFile string) (*Manager, error) {
	w, err := ifwatch.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("netlink subscribe: %w", err)
	}
	m := &Manager{watcher: w, ifaces: make(map[string]*Iface)}
	m.store = newStateStore(stateFile, m.collectState)
	for i := range cfgs {
		cfg := cfgs[i]
		if err := cfg.normalize(); err != nil {
			w.Close()
			return nil, err
		}
		if _, dup := m.ifaces[cfg.Name]; dup {
			w.Close()
			return nil, fmt.Errorf("duplicate interface %q", cfg.Name)
		}
		m.ifaces[cfg.Name] = newIface(cfg, w, m.store)
		m.order = append(m.order, cfg.Name)
	}
	return m, nil
}

// Start restores persisted state and launches everything.
func (m *Manager) Start() error {
	st, err := m.store.load()
	if err != nil {
		Emit("state_load_error", map[string]any{"error": err.Error()})
	}
	for name, it := range m.ifaces {
		it.restore(st.Ifaces[name])
	}
	for _, name := range m.order {
		m.ifaces[name].start()
	}
	Emit("ready", map[string]any{"ifaces": m.order})
	return nil
}

// Stop tears everything down (including PD-plumbed addresses and DNAT
// rules) and persists a final snapshot.
func (m *Manager) Stop() {
	for _, it := range m.ifaces {
		it.stop()
	}
	m.store.saveNow()
	m.watcher.Close()
}

func (m *Manager) collectState() persistedState {
	st := persistedState{Ifaces: map[string]*persistedIface{}}
	for name, it := range m.ifaces {
		st.Ifaces[name] = it.persisted()
	}
	return st
}

// --- API surface ---

func (m *Manager) iface(name string) (*Iface, error) {
	it, ok := m.ifaces[name]
	if !ok {
		return nil, fmt.Errorf("unknown interface %q", name)
	}
	return it, nil
}

// IfaceStatus is the status document of one interface.
type IfaceStatus struct {
	Name     string          `json:"name"`
	Tag      string          `json:"tag,omitempty"`
	Exists   bool            `json:"exists"`
	Up       bool            `json:"up"`
	MAC      string          `json:"mac,omitempty"`
	V4       []string        `json:"v4,omitempty"`
	V6       []string        `json:"v6,omitempty"`
	DHCP4    bool            `json:"dhcp4"`
	DHCP6    bool            `json:"dhcp6"`
	SLAAC    bool            `json:"slaac"`
	PDState      string `json:"pd_state,omitempty"`
	PDPrefix     string `json:"pd_prefix,omitempty"`
	PDRouteTable int    `json:"pd_route_table,omitempty"`
	Leases4  []Lease         `json:"leases4"`
	Leases6  []Lease         `json:"leases6"`
	Statics4 []StaticBinding `json:"statics4"`
	Statics6 []StaticBinding `json:"statics6"`
}

// Status reports all interfaces, stable order.
func (m *Manager) Status() []IfaceStatus {
	out := make([]IfaceStatus, 0, len(m.order))
	for _, name := range m.order {
		it := m.ifaces[name]
		st := it.snapshot()
		s := IfaceStatus{
			Name:     name,
			Tag:      it.cfg.Tag,
			Exists:   st.Exists,
			Up:       st.Up,
			DHCP4:    it.cfg.DHCP4.Enabled,
			DHCP6:    it.cfg.DHCP6.Enabled,
			SLAAC:    it.cfg.SLAAC,
			Leases4:  it.d4.Leases(),
			Leases6:  it.d6.Leases(),
			Statics4: it.d4.ListStatic(),
			Statics6: it.d6.ListStatic(),
		}
		if len(st.MAC) > 0 {
			s.MAC = st.MAC.String()
		}
		for _, p := range st.V4 {
			s.V4 = append(s.V4, p.String())
		}
		for _, p := range st.V6 {
			s.V6 = append(s.V6, p.String())
		}
		if it.pdc != nil {
			s.PDState = it.pdc.State()
			if b := it.pdc.Binding(); b != nil {
				s.PDPrefix = b.Prefix.String()
			}
			s.PDRouteTable = it.cfg.PD.RouteTable
		}
		sortStatics(s.Statics4)
		sortStatics(s.Statics6)
		out = append(out, s)
	}
	return out
}

func sortStatics(bs []StaticBinding) {
	sort.Slice(bs, func(i, j int) bool { return bs[i].ID < bs[j].ID })
}

// Leases returns one interface's active leases for a family (4 or 6).
func (m *Manager) Leases(name string, family int) ([]Lease, error) {
	it, err := m.iface(name)
	if err != nil {
		return nil, err
	}
	switch family {
	case 4:
		return it.d4.Leases(), nil
	case 6:
		return it.d6.Leases(), nil
	default:
		return nil, fmt.Errorf("family must be 4 or 6")
	}
}

// ReplaceStatics atomically replaces a family's static binding set.
func (m *Manager) ReplaceStatics(name string, family int, bs []StaticBinding) error {
	it, err := m.iface(name)
	if err != nil {
		return err
	}
	switch family {
	case 4:
		err = it.d4.ReplaceStatics(bs)
	case 6:
		err = it.d6.ReplaceStatics(bs)
	default:
		return fmt.Errorf("family must be 4 or 6")
	}
	if err == nil {
		m.store.markDirty()
	}
	return err
}

// PutStatic upserts one static binding.
func (m *Manager) PutStatic(name string, family int, b StaticBinding) error {
	it, err := m.iface(name)
	if err != nil {
		return err
	}
	switch family {
	case 4:
		err = it.d4.PutStatic(b)
	case 6:
		err = it.d6.PutStatic(b)
	default:
		return fmt.Errorf("family must be 4 or 6")
	}
	if err == nil {
		m.store.markDirty()
	}
	return err
}

// DeleteStatic removes one static binding by id.
func (m *Manager) DeleteStatic(name string, family int, id string) error {
	it, err := m.iface(name)
	if err != nil {
		return err
	}
	switch family {
	case 4:
		err = it.d4.DeleteStatic(id)
	case 6:
		err = it.d6.DeleteStatic(id)
	default:
		return fmt.Errorf("family must be 4 or 6")
	}
	if err == nil {
		m.store.markDirty()
	}
	return err
}

// DeleteLease force-releases an active lease.
func (m *Manager) DeleteLease(name string, ip netip.Addr) error {
	it, err := m.iface(name)
	if err != nil {
		return err
	}
	if ip.Is4() {
		return it.d4.ReleaseLease(ip)
	}
	return it.d6.ReleaseLease(ip)
}
