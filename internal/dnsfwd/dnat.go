package dnsfwd

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
)

// DNATRule redirects DNS traffic addressed to the served interface
// (dst=interface IP, dport=53) to the forwarder's actual port. Used when
// :53 is taken by something else and the forwarder listens elsewhere
// (e.g. 5335): guests keep using the gateway address on plain port 53.
//
// IPv4 only: stock Android GKI kernels ship without IPv6 NAT.
type DNATRule struct {
	iface string
	ip    string
	port  int
}

// InstallDNAT appends the REDIRECT rules (udp+tcp). Idempotence is handled
// with a delete-then-add pattern.
func InstallDNAT(iface, ip string, port int) (*DNATRule, error) {
	r := &DNATRule{iface: iface, ip: ip, port: port}
	r.Remove() // clear stale rules from a previous run
	for _, proto := range []string{"udp", "tcp"} {
		if err := iptables(append([]string{"-A"}, r.spec(proto)...)...); err != nil {
			r.Remove()
			return nil, fmt.Errorf("install %s DNAT: %w", proto, err)
		}
	}
	return r, nil
}

// Remove deletes the rules; safe to call when absent.
func (r *DNATRule) Remove() {
	for _, proto := range []string{"udp", "tcp"} {
		for {
			// loop: -D removes one instance per call
			if err := iptablesQuiet(append([]string{"-D"}, r.spec(proto)...)...); err != nil {
				break
			}
		}
	}
}

func (r *DNATRule) spec(proto string) []string {
	return []string{
		"PREROUTING", "-t", "nat",
		"-i", r.iface, "-d", r.ip, "-p", proto, "--dport", "53",
		"-j", "REDIRECT", "--to-ports", strconv.Itoa(r.port),
	}
}

func iptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		log.Printf("iptables %v: %v (%s)", args, err, out)
	}
	return err
}

func iptablesQuiet(args ...string) error {
	return exec.Command("iptables", args...).Run()
}
