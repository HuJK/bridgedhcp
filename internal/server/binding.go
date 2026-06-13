package server

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// StaticBinding pins an offset within the served prefix to a client matched
// by AND-ed conditions; nil fields are wildcards. Offsets — rather than
// concrete addresses — survive prefix changes (DHCPv6-PD renumbering): the
// concrete IP is computed against the live prefix at match time.
type StaticBinding struct {
	ID       string  `json:"id"`
	Order    int     `json:"order,omitempty"`
	MAC      *string `json:"mac,omitempty"`       // canonical form, e.g. "02:00:00:00:00:01"
	ClientID *string `json:"client_id,omitempty"` // lowercase hex (option 61 / DUID)
	Offset   uint64  `json:"offset"`              // address = prefix base + offset
}

func (b *StaticBinding) validate() error {
	if b.MAC == nil && b.ClientID == nil {
		return fmt.Errorf("static binding needs at least one condition")
	}
	if b.Offset == 0 {
		return fmt.Errorf("static binding offset must be > 0 (0 is the network base)")
	}
	return nil
}

// addrAtOffset computes base-of-prefix + offset, mirroring DroidVM's
// addressAtOffset semantics. Returns the invalid Addr when the result
// leaves the prefix.
func addrAtOffset(prefix netip.Prefix, offset uint64) netip.Addr {
	base := prefix.Masked().Addr()
	raw := base.AsSlice()
	v := new(big.Int).SetBytes(raw)
	v.Add(v, new(big.Int).SetUint64(offset))
	out := v.Bytes()
	if len(out) > len(raw) {
		return netip.Addr{}
	}
	buf := make([]byte, len(raw))
	copy(buf[len(raw)-len(out):], out)
	addr, ok := netip.AddrFromSlice(buf)
	if !ok || !prefix.Masked().Contains(addr) {
		return netip.Addr{}
	}
	return addr
}

// matchBinding picks the binding for a client: every non-wildcard condition
// must match; the binding matching the most conditions wins; ties go to the
// higher Order.
func matchBinding(bindings []*StaticBinding, mac, clientID string) *StaticBinding {
	var best *StaticBinding
	bestScore := 0
	for _, b := range bindings {
		score := 0
		if b.MAC != nil {
			if !strings.EqualFold(*b.MAC, mac) {
				continue
			}
			score++
		}
		if b.ClientID != nil {
			if !strings.EqualFold(*b.ClientID, clientID) {
				continue
			}
			score++
		}
		if score == 0 {
			continue
		}
		if best == nil || score > bestScore || (score == bestScore && b.Order > best.Order) {
			best = b
			bestScore = score
		}
	}
	return best
}

// buildStaticSet validates a full binding set (unique non-empty IDs) and
// returns it as a map, for atomic replacement.
func buildStaticSet(bs []StaticBinding) (map[string]*StaticBinding, error) {
	m := make(map[string]*StaticBinding, len(bs))
	for i := range bs {
		b := bs[i]
		if b.ID == "" {
			return nil, fmt.Errorf("static binding needs an id")
		}
		if err := b.validate(); err != nil {
			return nil, fmt.Errorf("binding %q: %w", b.ID, err)
		}
		if _, dup := m[b.ID]; dup {
			return nil, fmt.Errorf("duplicate binding id %q", b.ID)
		}
		m[b.ID] = &b
	}
	return m, nil
}

// Lease is one address assignment.
type Lease struct {
	IP       netip.Addr `json:"ip"`
	MAC      string     `json:"mac"`
	ClientID string     `json:"client_id,omitempty"`
	Hostname string     `json:"hostname,omitempty"`
	Expiry   time.Time  `json:"expiry"`
	Static   bool       `json:"static,omitempty"`
}

// leaseTable tracks active leases for one address family on one interface.
type leaseTable struct {
	mu      sync.Mutex
	leases  map[netip.Addr]*Lease
	now     func() time.Time
	changed func() // persistence hook, called outside the lock
}

func newLeaseTable() *leaseTable {
	return &leaseTable{leases: make(map[netip.Addr]*Lease), now: time.Now}
}

func (t *leaseTable) notify() {
	if t.changed != nil {
		t.changed()
	}
}

// clientKey identifies a client for lease reuse.
func clientKey(mac, clientID string) string {
	return strings.ToLower(mac) + "/" + strings.ToLower(clientID)
}

// byClient finds the client's active lease.
func (t *leaseTable) byClient(mac, clientID string) *Lease {
	key := clientKey(mac, clientID)
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.leases {
		if clientKey(l.MAC, l.ClientID) == key && !t.now().After(l.Expiry) {
			cp := *l
			return &cp
		}
	}
	return nil
}

func (t *leaseTable) set(l Lease) {
	t.mu.Lock()
	t.leases[l.IP] = &l
	t.mu.Unlock()
	t.notify()
}

func (t *leaseTable) release(ip netip.Addr) bool {
	t.mu.Lock()
	_, ok := t.leases[ip]
	if ok {
		delete(t.leases, ip)
	}
	t.mu.Unlock()
	if ok {
		t.notify()
	}
	return ok
}

// inUse reports whether ip currently has an unexpired lease held by a
// different client.
func (t *leaseTable) inUse(ip netip.Addr, mac, clientID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	l := t.leases[ip]
	if l == nil || t.now().After(l.Expiry) {
		return false
	}
	return clientKey(l.MAC, l.ClientID) != clientKey(mac, clientID)
}

func (t *leaseTable) expireSweep() {
	now := t.now()
	removed := false
	t.mu.Lock()
	for ip, l := range t.leases {
		if now.After(l.Expiry) {
			delete(t.leases, ip)
			removed = true
		}
	}
	t.mu.Unlock()
	if removed {
		t.notify()
	}
}

func (t *leaseTable) snapshot() []Lease {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Lease, 0, len(t.leases))
	now := t.now()
	for _, l := range t.leases {
		if now.After(l.Expiry) {
			continue
		}
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// load replaces the table contents (state restore at startup).
func (t *leaseTable) load(ls []Lease) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.leases = make(map[netip.Addr]*Lease, len(ls))
	for i := range ls {
		l := ls[i]
		if l.IP.IsValid() {
			t.leases[l.IP] = &l
		}
	}
}

// allocate finds a free address in [start, end], skipping skip() addresses
// and active leases, and records the lease. Returns the invalid Addr when
// the pool is exhausted.
func (t *leaseTable) allocate(start, end netip.Addr, skip func(netip.Addr) bool, l Lease) netip.Addr {
	t.mu.Lock()
	now := t.now()
	for ip := start; ip.IsValid() && !end.Less(ip); ip = ip.Next() {
		if skip(ip) {
			continue
		}
		if cur, ok := t.leases[ip]; ok && !now.After(cur.Expiry) {
			continue
		}
		l.IP = ip
		t.leases[ip] = &l
		t.mu.Unlock()
		t.notify()
		return ip
	}
	t.mu.Unlock()
	return netip.Addr{}
}

// hwAddrString canonicalizes a MAC for keying.
func hwAddrString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}

// u32 reads a big-endian uint32 (helper for IAID handling).
func u32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
