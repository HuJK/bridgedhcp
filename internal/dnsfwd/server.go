package dnsfwd

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Server is one interface's DNS listener (UDP + TCP). The sockets are
// wildcard-bound with SO_BINDTODEVICE, so interface renumbering needs no
// rebinding and only frames from the served interface are accepted.
type Server struct {
	iface    string
	port     int
	upstream Upstream

	udp *net.UDPConn
	tcp net.Listener

	mu     sync.Mutex
	closed bool
}

// New starts the listeners on [::]:port bound to iface.
func New(iface string, port int, upstream Upstream) (*Server, error) {
	s := &Server{iface: iface, port: port, upstream: upstream}
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
				if serr == nil {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", net.JoinHostPort("", itoa(port)))
	if err != nil {
		return nil, err
	}
	s.udp = pc.(*net.UDPConn)
	ln, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort("", itoa(port)))
	if err != nil {
		pc.Close()
		return nil, err
	}
	s.tcp = ln
	go s.serveUDP()
	go s.serveTCP()
	return s, nil
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// Port reports the actually bound UDP port (for port=0 in tests).
func (s *Server) Port() int {
	return s.udp.LocalAddr().(*net.UDPAddr).Port
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.udp.Close()
	s.tcp.Close()
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, peer, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			if s.isClosed() {
				return
			}
			continue
		}
		if n < 12 {
			continue // shorter than a DNS header
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		go func(q []byte, peer *net.UDPAddr) {
			ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
			defer cancel()
			ans, err := s.upstream.Exchange(ctx, q, false)
			if err != nil {
				log.Printf("dns[%s]: upstream: %v", s.iface, err)
				ans = servfail(q)
			}
			_, _ = s.udp.WriteToUDP(ans, peer)
		}(q, peer)
	}
}

func (s *Server) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if s.isClosed() {
				return
			}
			continue
		}
		go s.serveTCPConn(conn)
	}
}

func (s *Server) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, q); err != nil {
			return
		}
		if len(q) < 12 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		ans, err := s.upstream.Exchange(ctx, q, true)
		cancel()
		if err != nil {
			log.Printf("dns[%s]: upstream: %v", s.iface, err)
			ans = servfail(q)
		}
		out := make([]byte, 2+len(ans))
		binary.BigEndian.PutUint16(out, uint16(len(ans)))
		copy(out[2:], ans)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// servfail builds a SERVFAIL response echoing the query header/question.
func servfail(q []byte) []byte {
	out := make([]byte, len(q))
	copy(out, q)
	out[2] |= 0x80          // QR
	out[3] = out[3]&0xF0 | 2 // RCODE = SERVFAIL
	return out
}
