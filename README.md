# bridgedhcp

DHCPv4 / DHCPv6 / SLAAC (router advertisements) server for Linux bridge
interfaces, with a built-in DHCPv6-PD client and an optional per-interface
DNS forwarder. Designed as the network-services companion of a VM host
daemon (DroidVM), but fully standalone: one static Go binary, no libc.

Why not dnsmasq: Android ships a 2009-era dnsmasq 2.51 that predates
DHCPv6 entirely, and shipping a modern C build means an NDK toolchain and
GPL distribution obligations. This reuses the already-tested protocol
logic of gvisor-vswitch's gateway over an AF_PACKET transport.

## Design

- **One AF_PACKET socket per served interface** with a cBPF filter that
  admits only UDP:67 (DHCPv4), UDP:547 (DHCPv6) and ICMPv6 router
  solicitations. Replies are crafted frames with fully computed checksums.
  Inbound L4 checksums are never validated: frames originating from virtio
  guests routinely arrive CHECKSUM_PARTIAL (TX offload).
- **Everything is offset-based.** Pools and static leases are expressed as
  offsets from the interface's *live* prefix (`address = prefix base +
  offset`). When the prefix changes — a DHCPv6-PD renumbering — pools and
  static leases follow automatically; nothing needs rewriting.
- **The interface's addresses are the single source of truth**, tracked
  via netlink subscription. The PD client materializes its delegation as
  an address on the interface; DHCPv6/RA serve whatever is there. A
  withdrawn prefix is advertised a few more times with zero lifetimes so
  clients deprecate it immediately.
- **PD roaming**: while the held delegation is valid, a link change
  triggers confirmation (RENEW, then multicast REBIND) instead of
  re-soliciting — roaming between APs of the same network keeps the
  prefix. Confirmation is only attempted when the uplink is actually
  usable (up + non-tentative link-local), so the down-phase of a roam is
  never mistaken for "this network has no PD server". Moving to a network
  without PD withdraws the prefix and stops DHCPv6/SLAAC. Delegations,
  leases and static bindings persist across restarts in `state_file`.
- **Routed-prefix mode** (`pd.route_table`): the delegated prefix is
  policy-routed instead of relying on the host's own connectivity — guests
  use their PD addresses end to end, which works even on RA-A=0 networks
  where Android (no DHCPv6 client) holds no global address itself. A
  dedicated routing table carries the on-link subnet plus a default route
  mirrored from the uplink's RA-learned router; a `from`/`to` rule pair on
  the prefix selects it (both directions are needed: Android's own rules
  only route `iif lo` traffic). Two strictly separated lifecycles:
  sysctls (uplink `accept_ra` 1→2 and per-interface `forwarding`, ordered
  so the host never drops RAs) live for the process and are refcounted per
  uplink; everything that encodes the prefix — rules, routes, table
  content — is wiped the moment the delegation is lost, leaving no trace.
  The table id is the crash-cleanup key: startup wipes whatever still
  points at the table, so give each interface a **stable** id across
  restarts (e.g. 9991, 9992, ...). `rule_priority` defaults to 5000
  (after the local-table rule, before Android's 10000+ policy rules).
- **DNS forwarder** per interface (UDP+TCP, wildcard socket with
  `SO_BINDTODEVICE`). Upstream order: Android's `/dev/socket/dnsproxyd`
  (the bionic resolver path — Private DNS/DoT/DoH and DNSSEC apply),
  explicitly configured servers, `/etc/resolv.conf`. With
  `"redirect_53": true` and a non-53 port, an iptables REDIRECT maps
  `dst=<interface IP>:53` to the real port (IPv4 only: stock Android GKI
  kernels have no IPv6 NAT).
- **Control API over a unix socket** (no host port) with a bearer key.
  Single-line JSON events on stdout (`ready`, `attached`, `pd_prefix`,
  `pd_lost`, `dns_ready`) for a supervising daemon; logs go to stderr.

## Usage

```sh
bridgedhcp --config /path/config.json
bridgedhcp --config /path/config.json --check   # validate only
```

```json
{
  "api_socket": "/run/bridgedhcp.sock",
  "api_key_file": "/run/bridgedhcp.key",
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
      "dhcp6": { "pool_offset_start": 128, "pool_offset_end": 192 },
      "slaac": true,
      "pd": {
        "uplink": "wlan0",
        "duid": "00:03:00:01:02:aa:bb:cc:dd:ee",
        "iaid": 1,
        "suffix": "::1",
        "prefix_len": 64,
        "route_table": 9991,
        "rule_priority": 5000
      },
      "dns": { "port": 5335, "redirect_53": true, "upstream": "auto" },
      "statics4": [ { "id": "vm1", "mac": "02:00:00:00:00:05", "offset": 5 } ]
    }
  ]
}
```

### API

`bridgedhcp ctl --socket <sock> --key <key> <command>` or HTTP over the
unix socket with `Authorization: Bearer <key>`:

| Method/Path | Purpose |
|---|---|
| `GET /v1/status` | all interfaces: addresses, PD state, leases, statics |
| `GET /v1/ifaces/{if}/leases/{4\|6}` | active leases |
| `PUT /v1/ifaces/{if}/statics/{4\|6}` | replace static set (`{"statics":[...]}`) |
| `POST /v1/ifaces/{if}/statics/{4\|6}` | upsert one static binding |
| `DELETE /v1/ifaces/{if}/statics/{4\|6}/{id}` | delete one static binding |
| `DELETE /v1/ifaces/{if}/leases/{ip}` | force-release a lease |
| `POST /v1/ifaces/{if}/pd/renew` | refresh the PD delegation now (RENEW/REBIND, same prefix) |
| `POST /v1/ifaces/{if}/pd/release` | release the PD delegation (RELEASE) and re-solicit |

## Building & testing

```sh
make build-android       # static linux/arm64
make build-linux-amd64
make test                # unit tests (-race)
make test-integration    # root only: netns/veth scenarios
```

The integration suite simulates, with network namespaces: the full DORA
handshake (pure-Go client), offset statics via the API, lease persistence
across restarts, kernel SLAAC autoconfiguration from our RAs, stateful
DHCPv6, the complete PD lifecycle (acquire → same-L2 roam keeps the prefix
via REBIND → PD-less network withdraws it), and the DNS forwarder
including the :53 REDIRECT path.
