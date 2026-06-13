package dnsfwd

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// AndroidUpstream resolves through netd's DNS proxy socket — the same path
// bionic's resolver uses — so answers benefit from the system's Private
// DNS (DoT/DoH), DNSSEC validation and per-network resolver config.
//
// Protocol (DnsResolver module, ResNSendHandler): one command per
// connection, "resnsend <flags> <netid> <base64url(query)>\0"; the
// response is a big-endian int32 (negative errno, or the rcode) followed,
// on success, by a big-endian uint32 length and the raw DNS answer.
type AndroidUpstream struct {
	socketPath string
	netID      uint32
}

const (
	dnsProxySocket = "/dev/socket/dnsproxyd"
	netidUnset     = 0
)

// NewAndroid returns nil when the dnsproxyd socket does not exist (not
// running on Android).
func NewAndroid() *AndroidUpstream {
	if _, err := os.Stat(dnsProxySocket); err != nil {
		return nil
	}
	return &AndroidUpstream{socketPath: dnsProxySocket, netID: netidUnset}
}

func (u *AndroidUpstream) Name() string { return "android-dnsproxyd" }

func (u *AndroidUpstream) Exchange(ctx context.Context, query []byte, _ bool) ([]byte, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", u.socketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(queryTimeout)
	}
	_ = conn.SetDeadline(dl)

	cmd := fmt.Sprintf("resnsend %d %d %s", 0, u.netID,
		base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(query))
	if _, err := conn.Write(append([]byte(cmd), 0)); err != nil {
		return nil, err
	}

	var code int32
	if err := binary.Read(conn, binary.BigEndian, &code); err != nil {
		return nil, fmt.Errorf("dnsproxyd read status: %w", err)
	}
	if code < 0 {
		return nil, fmt.Errorf("dnsproxyd error: %d", code)
	}
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, fmt.Errorf("dnsproxyd read length: %w", err)
	}
	if size == 0 || size > 65535 {
		return nil, fmt.Errorf("dnsproxyd bogus answer length %d", size)
	}
	ans := make([]byte, size)
	if _, err := io.ReadFull(conn, ans); err != nil {
		return nil, fmt.Errorf("dnsproxyd read answer: %w", err)
	}
	// sanity: answer must echo the query transaction id
	if len(ans) >= 2 && len(query) >= 2 && (ans[0] != query[0] || ans[1] != query[1]) {
		return nil, fmt.Errorf("dnsproxyd answer txid mismatch")
	}
	return ans, nil
}
