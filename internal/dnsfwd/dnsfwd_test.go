package dnsfwd

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mockDNS answers every query with an A record 1.2.3.4 over UDP.
func mockDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			ans := buildAnswer(q)
			_, _ = pc.WriteTo(ans, peer)
		}
	}()
	return pc.LocalAddr().String()
}

// buildAnswer crafts a minimal response: echo header+question, append one
// A record via a compression pointer to the question name.
func buildAnswer(q []byte) []byte {
	out := append([]byte(nil), q...)
	out[2] |= 0x80                       // QR
	binary.BigEndian.PutUint16(out[6:8], 1) // ANCOUNT
	rr := []byte{
		0xC0, 0x0C, // name: pointer to offset 12
		0, 1, 0, 1, // TYPE A, CLASS IN
		0, 0, 0, 60, // TTL
		0, 4, 1, 2, 3, 4, // RDATA
	}
	return append(out, rr...)
}

// buildQuery crafts a minimal A query for name.
func buildQuery(txid uint16, name string) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], txid)
	q[2] = 0x01 // RD
	binary.BigEndian.PutUint16(q[4:6], 1)
	for _, label := range splitDots(name) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	return q
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestStaticUpstreamExchange(t *testing.T) {
	server := mockDNS(t)
	up := NewStatic([]string{server})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := buildQuery(0x1234, "example.com")
	ans, err := up.Exchange(ctx, q, false)
	if err != nil {
		t.Fatal(err)
	}
	if ans[0] != q[0] || ans[1] != q[1] {
		t.Fatal("txid mismatch")
	}
	if ans[2]&0x80 == 0 {
		t.Fatal("not a response")
	}
}

func TestChainFallsThrough(t *testing.T) {
	dead := NewStatic([]string{"127.0.0.1:1"}) // closed port
	live := NewStatic([]string{mockDNS(t)})
	chain := NewChain(dead, live)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := chain.Exchange(ctx, buildQuery(7, "x.test"), false); err != nil {
		t.Fatalf("chain did not fall through: %v", err)
	}
}

func TestResolvConfParseAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("# c\nnameserver 9.9.9.9\nnameserver fd00::53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	up := NewResolvConf(path)
	servers := up.servers()
	want := []string{"9.9.9.9:53", "[fd00::53]:53"}
	if len(servers) != 2 || servers[0] != want[0] || servers[1] != want[1] {
		t.Fatalf("servers %v, want %v", servers, want)
	}
}

func TestServerForwardsOnLoopback(t *testing.T) {
	upstreamAddr := mockDNS(t)
	srv, err := New("lo", 0, NewStatic([]string{upstreamAddr}))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", srv.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	q := buildQuery(0xBEEF, "guest.test")
	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	ans := buf[:n]
	if ans[0] != q[0] || ans[1] != q[1] || ans[2]&0x80 == 0 {
		t.Fatal("bad answer through forwarder")
	}
	if binary.BigEndian.Uint16(ans[6:8]) != 1 {
		t.Fatal("no answer RR")
	}
}

func TestServfailShape(t *testing.T) {
	q := buildQuery(0xAA, "a.b")
	f := servfail(q)
	if f[0] != q[0] || f[1] != q[1] || f[2]&0x80 == 0 || f[3]&0x0F != 2 {
		t.Fatalf("servfail malformed: % x", f[:4])
	}
}
