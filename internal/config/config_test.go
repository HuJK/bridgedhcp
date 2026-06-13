package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sample = `{
  "api_socket": "/run/bridgedhcp.sock",
  "api_key": "secret",
  "state_file": "/run/bridgedhcp.state.json",
  "interfaces": [
    {
      "name": "br0vAA",
      "tag": "vlan0",
      "dhcp4": {
        "pool_offset_start": 128,
        "pool_offset_end": 192,
        "lease_time": "12h",
        "dns": ["8.8.8.8", "1.1.1.1"]
      },
      "dhcp6": {
        "pool_offset_start": 128,
        "pool_offset_end": 192,
        "lease_time": "12h"
      },
      "slaac": true,
      "pd": {
        "uplink": "wlan0",
        "duid": "00:03:00:01:02:aa:bb:cc:dd:ee",
        "iaid": 7,
        "suffix": "::1",
        "prefix_len": 64
      },
      "dns": {
        "port": 5335,
        "redirect_53": true,
        "upstream": "auto"
      },
      "statics4": [
        {"id": "vm-a", "mac": "02:00:00:00:00:05", "offset": 5}
      ]
    }
  ]
}`

func TestLoadAndBuild(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.ResolveAPIKey()
	if err != nil || key != "secret" {
		t.Fatalf("key %q err %v", key, err)
	}
	cfgs, err := f.BuildIfaceConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("got %d ifaces", len(cfgs))
	}
	c := cfgs[0]
	if !c.DHCP4.Enabled || c.DHCP4.PoolOffsetStart != 128 || c.DHCP4.LeaseTime != 12*time.Hour {
		t.Fatalf("dhcp4 %+v", c.DHCP4)
	}
	if len(c.DHCP4.DNS) != 2 || c.DHCP4.DNS[0].String() != "8.8.8.8" {
		t.Fatalf("dhcp4 dns %v", c.DHCP4.DNS)
	}
	if !c.SLAAC || !c.DHCP6.Enabled {
		t.Fatal("v6 services not enabled")
	}
	if c.PD == nil || c.PD.Uplink != "wlan0" || c.PD.IAID != 7 {
		t.Fatalf("pd %+v", c.PD)
	}
	wantDUID := []byte{0x00, 0x03, 0x00, 0x01, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	if len(c.PD.DUID) != len(wantDUID) {
		t.Fatalf("duid %x", c.PD.DUID)
	}
	for i := range wantDUID {
		if c.PD.DUID[i] != wantDUID[i] {
			t.Fatalf("duid %x", c.PD.DUID)
		}
	}
	if c.DNS == nil || c.DNS.Port != 5335 || !c.DNS.Redirect53 {
		t.Fatalf("dns %+v", c.DNS)
	}
	statics := f.InitialStatics()
	if st, ok := statics["br0vAA"]; !ok || len(st[0]) != 1 || st[0][0].Offset != 5 {
		t.Fatalf("statics %+v", statics)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	bad := `{"api_socket":"/s","api_key":"k","interfaces":[{"name":"x","bogus_field":1}]}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestDurationForms(t *testing.T) {
	var d Duration
	if err := d.UnmarshalJSON([]byte(`"90m"`)); err != nil || time.Duration(d) != 90*time.Minute {
		t.Fatalf("string form: %v %v", d, err)
	}
	if err := d.UnmarshalJSON([]byte(`30`)); err != nil || time.Duration(d) != 30*time.Second {
		t.Fatalf("numeric form: %v %v", d, err)
	}
}

func buildPD(t *testing.T, pds ...map[string]any) error {
	t.Helper()
	ifaces := make([]Iface, 0, len(pds))
	for i, pd := range pds {
		p := &PD{Uplink: "wlan0", DUID: "00:03:00:01:02:aa:bb:cc:dd:ee"}
		if v, ok := pd["route_table"]; ok {
			p.RouteTable = v.(int)
		}
		if v, ok := pd["rule_priority"]; ok {
			p.RulePriority = v.(int)
		}
		ifaces = append(ifaces, Iface{Name: fmt.Sprintf("br%d", i), PD: p})
	}
	f := &File{APISocket: "/run/x.sock", Interfaces: ifaces}
	_, err := f.BuildIfaceConfigs()
	return err
}

func TestPDRouteTableValidation(t *testing.T) {
	if err := buildPD(t, map[string]any{"route_table": 9991}); err != nil {
		t.Fatalf("valid table rejected: %v", err)
	}
	for _, reserved := range []int{253, 254, 255, 97} {
		if err := buildPD(t, map[string]any{"route_table": reserved}); err == nil {
			t.Fatalf("reserved table %d accepted", reserved)
		}
	}
	if err := buildPD(t, map[string]any{"route_table": -1}); err == nil {
		t.Fatal("negative table accepted")
	}
	// duplicate across interfaces
	if err := buildPD(t,
		map[string]any{"route_table": 9991},
		map[string]any{"route_table": 9991}); err == nil {
		t.Fatal("duplicate table accepted")
	}
	// distinct tables fine
	if err := buildPD(t,
		map[string]any{"route_table": 9991},
		map[string]any{"route_table": 9992}); err != nil {
		t.Fatalf("distinct tables rejected: %v", err)
	}
	// rule_priority without route_table
	if err := buildPD(t, map[string]any{"rule_priority": 5000}); err == nil {
		t.Fatal("rule_priority without route_table accepted")
	}
	if err := buildPD(t, map[string]any{"route_table": 9991, "rule_priority": 40000}); err == nil {
		t.Fatal("out-of-range rule_priority accepted")
	}
}
