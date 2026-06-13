// Package config maps the JSON config file onto server configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/HuJK/bridgedhcp/internal/server"
)

// Duration accepts "12h" / "30m" style strings in JSON.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var secs float64
	if err := json.Unmarshal(b, &secs); err != nil {
		return fmt.Errorf("duration must be a string or seconds")
	}
	*d = Duration(time.Duration(secs * float64(time.Second)))
	return nil
}

// File is the top-level config document.
type File struct {
	APISocket  string  `json:"api_socket"`
	APIKey     string  `json:"api_key,omitempty"`
	APIKeyFile string  `json:"api_key_file,omitempty"`
	StateFile  string  `json:"state_file,omitempty"`
	Interfaces []Iface `json:"interfaces"`
}

// Iface is one served interface.
type Iface struct {
	Name  string  `json:"name"`
	Tag   string  `json:"tag,omitempty"`
	DHCP4 *Pool   `json:"dhcp4,omitempty"`
	DHCP6 *Pool   `json:"dhcp6,omitempty"`
	SLAAC bool    `json:"slaac,omitempty"`
	PD    *PD     `json:"pd,omitempty"`
	DNS   *DNS    `json:"dns,omitempty"`
	RA    *RAOpts `json:"ra,omitempty"`

	Statics4 []server.StaticBinding `json:"statics4,omitempty"`
	Statics6 []server.StaticBinding `json:"statics6,omitempty"`
}

// Pool configures one DHCP family; offsets are relative to the live prefix.
type Pool struct {
	PoolOffsetStart uint64   `json:"pool_offset_start"`
	PoolOffsetEnd   uint64   `json:"pool_offset_end"`
	LeaseTime       Duration `json:"lease_time,omitempty"`
	DNS             []string `json:"dns,omitempty"`
}

// PD configures the DHCPv6-PD client feeding this interface.
type PD struct {
	Uplink    string `json:"uplink"`
	DUID      string `json:"duid"`             // "00:03:00:01:aa:bb:cc:dd:ee:ff"
	IAID      uint32 `json:"iaid,omitempty"`   // default 1
	Suffix    string `json:"suffix,omitempty"` // default "::1"
	PrefixLen int    `json:"prefix_len,omitempty"`

	// RouteTable enables routed-prefix mode: guest traffic carrying the
	// delegated prefix is policy-routed through this dedicated table
	// (uplink forwarding + accept_ra=2 managed for the process lifetime;
	// rules/routes follow the prefix lifetime). The id must be stable
	// across restarts — it is the crash-cleanup key. 0 = disabled.
	RouteTable int `json:"route_table,omitempty"`
	// RulePriority of the from/to rule pair; default 5000 (after the
	// local-table rule at 0, before Android's 10000+ policy rules).
	RulePriority int `json:"rule_priority,omitempty"`

	// retransmission tuning (defaults: 1s initial, 32s cap, 6 attempts)
	InitialTimeout Duration `json:"initial_timeout,omitempty"`
	MaxTimeout     Duration `json:"max_timeout,omitempty"`
	Attempts       int      `json:"attempts,omitempty"`
}

// DNS configures the per-interface DNS forwarder.
type DNS struct {
	Port       int      `json:"port,omitempty"` // default 53
	Redirect53 bool     `json:"redirect_53,omitempty"`
	Upstream   string   `json:"upstream,omitempty"` // auto | android | resolv
	Upstreams  []string `json:"upstreams,omitempty"`
}

// RAOpts overrides RA timing.
type RAOpts struct {
	Interval       Duration `json:"interval,omitempty"`
	RouterLifetime Duration `json:"router_lifetime,omitempty"`
	ValidLifetime  Duration `json:"valid_lifetime,omitempty"`
	PreferredLife  Duration `json:"preferred_lifetime,omitempty"`
	DNS            []string `json:"dns,omitempty"` // RDNSS
}

// Load reads and validates a config file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.APISocket == "" {
		return nil, fmt.Errorf("%s: api_socket is required", path)
	}
	if len(f.Interfaces) == 0 {
		return nil, fmt.Errorf("%s: no interfaces configured", path)
	}
	return &f, nil
}

// ResolveAPIKey returns the literal key or the key file contents.
func (f *File) ResolveAPIKey() (string, error) {
	if f.APIKey != "" {
		return f.APIKey, nil
	}
	if f.APIKeyFile != "" {
		data, err := os.ReadFile(f.APIKeyFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", fmt.Errorf("api_key or api_key_file is required")
}

// reservedTables are kernel-reserved routing table ids (unspec, default,
// main, local) plus Android's local_network range (97-99).
func reservedTable(t int) bool {
	switch t {
	case 0, 253, 254, 255, 97, 98, 99:
		return true
	}
	return false
}

// BuildIfaceConfigs converts the file form into server configs.
func (f *File) BuildIfaceConfigs() ([]server.IfaceConfig, error) {
	tables := make(map[int]string)
	out := make([]server.IfaceConfig, 0, len(f.Interfaces))
	for _, ic := range f.Interfaces {
		cfg := server.IfaceConfig{Name: ic.Name, Tag: ic.Tag, SLAAC: ic.SLAAC}
		if ic.DHCP4 != nil {
			dns, err := parseAddrs(ic.DHCP4.DNS, "dhcp4 dns")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", ic.Name, err)
			}
			cfg.DHCP4 = server.DHCP4Config{
				Enabled:         true,
				PoolOffsetStart: ic.DHCP4.PoolOffsetStart,
				PoolOffsetEnd:   ic.DHCP4.PoolOffsetEnd,
				LeaseTime:       time.Duration(ic.DHCP4.LeaseTime),
				DNS:             dns,
			}
		}
		if ic.DHCP6 != nil {
			dns, err := parseAddrs(ic.DHCP6.DNS, "dhcp6 dns")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", ic.Name, err)
			}
			cfg.DHCP6 = server.DHCP6Config{
				Enabled:         true,
				PoolOffsetStart: ic.DHCP6.PoolOffsetStart,
				PoolOffsetEnd:   ic.DHCP6.PoolOffsetEnd,
				LeaseTime:       time.Duration(ic.DHCP6.LeaseTime),
				DNS:             dns,
			}
		}
		if ic.RA != nil {
			dns, err := parseAddrs(ic.RA.DNS, "ra dns")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", ic.Name, err)
			}
			cfg.RA = server.RAConfig{
				Interval:       time.Duration(ic.RA.Interval),
				RouterLifetime: time.Duration(ic.RA.RouterLifetime),
				ValidLifetime:  time.Duration(ic.RA.ValidLifetime),
				PreferredLife:  time.Duration(ic.RA.PreferredLife),
				DNS:            dns,
			}
		}
		if ic.PD != nil {
			duid, err := parseDUID(ic.PD.DUID)
			if err != nil {
				return nil, fmt.Errorf("%s: pd duid: %w", ic.Name, err)
			}
			iaid := ic.PD.IAID
			if iaid == 0 {
				iaid = 1
			}
			if rt := ic.PD.RouteTable; rt != 0 {
				if rt < 0 || rt > 0xfffffffe || reservedTable(rt) {
					return nil, fmt.Errorf("%s: pd route_table %d is reserved or out of range", ic.Name, rt)
				}
				if prev, dup := tables[rt]; dup {
					return nil, fmt.Errorf("%s: pd route_table %d already used by %s", ic.Name, rt, prev)
				}
				tables[rt] = ic.Name
				if p := ic.PD.RulePriority; p < 0 || p > 32765 {
					return nil, fmt.Errorf("%s: pd rule_priority %d out of range (0-32765)", ic.Name, p)
				}
			} else if ic.PD.RulePriority != 0 {
				return nil, fmt.Errorf("%s: pd rule_priority needs route_table", ic.Name)
			}
			pdCfg := &server.PDConfig{
				Uplink:         ic.PD.Uplink,
				DUID:           duid,
				IAID:           iaid,
				PrefixLen:      ic.PD.PrefixLen,
				RouteTable:     ic.PD.RouteTable,
				RulePriority:   ic.PD.RulePriority,
				InitialTimeout: time.Duration(ic.PD.InitialTimeout),
				MaxTimeout:     time.Duration(ic.PD.MaxTimeout),
				Attempts:       ic.PD.Attempts,
			}
			if ic.PD.Suffix != "" {
				sfx, err := netip.ParseAddr(ic.PD.Suffix)
				if err != nil || !sfx.Is6() {
					return nil, fmt.Errorf("%s: pd suffix %q invalid", ic.Name, ic.PD.Suffix)
				}
				pdCfg.Suffix = sfx
			}
			cfg.PD = pdCfg
		}
		if ic.DNS != nil {
			cfg.DNS = &server.DNSConfig{
				Port:       ic.DNS.Port,
				Redirect53: ic.DNS.Redirect53,
				Upstream:   ic.DNS.Upstream,
				Upstreams:  ic.DNS.Upstreams,
			}
		}
		out = append(out, cfg)
	}
	return out, nil
}

// InitialStatics returns the configured static bindings per interface.
func (f *File) InitialStatics() map[string][2][]server.StaticBinding {
	out := make(map[string][2][]server.StaticBinding)
	for _, ic := range f.Interfaces {
		if len(ic.Statics4) > 0 || len(ic.Statics6) > 0 {
			out[ic.Name] = [2][]server.StaticBinding{ic.Statics4, ic.Statics6}
		}
	}
	return out
}

func parseAddrs(in []string, what string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range in {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", what, s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func parseDUID(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) < 4 || len(s)%2 != 0 {
		return nil, fmt.Errorf("bad duid %q", s)
	}
	out := make([]byte, len(s)/2)
	if _, err := fmt.Sscanf(s, "%x", &out); err != nil {
		return nil, fmt.Errorf("bad duid %q", s)
	}
	return out, nil
}
