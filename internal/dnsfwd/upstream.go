// Package dnsfwd is a small DNS forwarder: queries from served interfaces
// are relayed verbatim to an upstream resolver chain. On Android the
// preferred upstream is the system resolver (netd's dnsproxyd socket),
// which transparently provides Private DNS (DoT/DoH) and DNSSEC; the
// fallbacks are explicitly configured servers and /etc/resolv.conf.
package dnsfwd

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const queryTimeout = 5 * time.Second

// Upstream resolves one raw DNS query to a raw answer.
type Upstream interface {
	Name() string
	// Exchange returns the raw DNS response. transportTCP hints that the
	// client asked over TCP (so a large answer is fine).
	Exchange(ctx context.Context, query []byte, transportTCP bool) ([]byte, error)
}

// Chain tries upstreams in order until one answers.
type Chain struct {
	ups []Upstream
}

func NewChain(ups ...Upstream) *Chain { return &Chain{ups: ups} }

func (c *Chain) Name() string { return "chain" }

func (c *Chain) Exchange(ctx context.Context, query []byte, tcp bool) ([]byte, error) {
	var lastErr error
	for _, u := range c.ups {
		ans, err := u.Exchange(ctx, query, tcp)
		if err == nil {
			return ans, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstreams configured")
	}
	return nil, lastErr
}

// ServerListUpstream forwards to a fixed set of "ip" / "ip:port" servers.
type ServerListUpstream struct {
	name    string
	servers func() []string
}

// NewStatic builds an upstream over a fixed server list.
func NewStatic(servers []string) *ServerListUpstream {
	norm := normalizeServers(servers)
	return &ServerListUpstream{name: "static", servers: func() []string { return norm }}
}

// NewResolvConf builds an upstream that follows /etc/resolv.conf (re-read
// when its mtime changes).
func NewResolvConf(path string) *ServerListUpstream {
	if path == "" {
		path = "/etc/resolv.conf"
	}
	var mu sync.Mutex
	var cached []string
	var mtime time.Time
	load := func() []string {
		mu.Lock()
		defer mu.Unlock()
		st, err := os.Stat(path)
		if err != nil {
			return cached
		}
		if st.ModTime().Equal(mtime) && cached != nil {
			return cached
		}
		mtime = st.ModTime()
		cached = normalizeServers(parseResolvConf(path))
		return cached
	}
	return &ServerListUpstream{name: "resolv.conf", servers: load}
}

func parseResolvConf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

func normalizeServers(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			if strings.Contains(s, ":") && !strings.HasPrefix(s, "[") {
				s = "[" + s + "]:53" // bare IPv6
			} else {
				s = s + ":53"
			}
		}
		out = append(out, s)
	}
	return out
}

func (u *ServerListUpstream) Name() string { return u.name }

func (u *ServerListUpstream) Exchange(ctx context.Context, query []byte, tcp bool) ([]byte, error) {
	servers := u.servers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("%s: no nameservers", u.name)
	}
	var lastErr error
	for _, srv := range servers {
		var (
			ans []byte
			err error
		)
		if tcp {
			ans, err = exchangeTCP(ctx, srv, query)
		} else {
			ans, err = exchangeUDP(ctx, srv, query)
		}
		if err == nil {
			return ans, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func exchangeUDP(ctx context.Context, server string, query []byte) ([]byte, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		// match transaction id (kernel connect() already filters source)
		if n >= 2 && len(query) >= 2 && buf[0] == query[0] && buf[1] == query[1] {
			return buf[:n], nil
		}
	}
}

func exchangeTCP(ctx context.Context, server string, query []byte) ([]byte, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	ans := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, ans); err != nil {
		return nil, err
	}
	return ans, nil
}
