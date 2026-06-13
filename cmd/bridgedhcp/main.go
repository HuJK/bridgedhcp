// bridgedhcp serves DHCPv4, DHCPv6 and router advertisements on Linux
// bridge interfaces, with an optional DHCPv6-PD client per interface and a
// per-interface DNS forwarder. Control plane: HTTP over a unix socket with
// a bearer key ("bridgedhcp ctl ..." is the CLI client).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/HuJK/bridgedhcp/internal/api"
	"github.com/HuJK/bridgedhcp/internal/config"
	"github.com/HuJK/bridgedhcp/internal/server"
)

func main() {
	log.SetOutput(os.Stderr) // stdout is the machine-readable event stream

	if len(os.Args) > 1 && os.Args[1] == "ctl" {
		os.Exit(runCtl(os.Args[2:]))
	}
	os.Exit(runDaemon())
}

func runDaemon() int {
	fs := flag.NewFlagSet("bridgedhcp", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the JSON config file (required)")
	check := fs.Bool("check", false, "validate the config and exit")
	_ = fs.Parse(os.Args[1:])

	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "usage: bridgedhcp --config <file> | bridgedhcp ctl ...")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	key, err := cfg.ResolveAPIKey()
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	ifaceCfgs, err := cfg.BuildIfaceConfigs()
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	if *check {
		fmt.Println("config ok")
		return 0
	}

	mgr, err := server.NewManager(ifaceCfgs, cfg.StateFile)
	if err != nil {
		log.Printf("init: %v", err)
		return 1
	}
	// config-file statics are the baseline; persisted (API-managed) sets
	// override them in Start()'s restore when non-empty
	for name, st := range cfg.InitialStatics() {
		if len(st[0]) > 0 {
			if err := mgr.ReplaceStatics(name, 4, st[0]); err != nil {
				log.Printf("statics4 %s: %v", name, err)
				return 1
			}
		}
		if len(st[1]) > 0 {
			if err := mgr.ReplaceStatics(name, 6, st[1]); err != nil {
				log.Printf("statics6 %s: %v", name, err)
				return 1
			}
		}
	}
	if err := mgr.Start(); err != nil {
		log.Printf("start: %v", err)
		return 1
	}

	apiSrv, err := api.New(mgr, cfg.APISocket, key)
	if err != nil {
		log.Printf("api: %v", err)
		mgr.Stop()
		return 1
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
	apiSrv.Close()
	mgr.Stop()
	return 0
}

// --- ctl: tiny API client ---

func runCtl(args []string) int {
	fs := flag.NewFlagSet("bridgedhcp ctl", flag.ExitOnError)
	socket := fs.String("socket", "", "API unix socket path (required)")
	key := fs.String("key", "", "API key")
	keyFile := fs.String("key-file", "", "file containing the API key")
	_ = fs.Parse(args)
	rest := fs.Args()

	if *socket == "" || len(rest) == 0 {
		fmt.Fprintln(os.Stderr, `usage: bridgedhcp ctl --socket <path> --key <key> <command>
commands:
  status
  leases <iface> <4|6>
  statics-replace <iface> <4|6>   (JSON {"statics":[...]} on stdin)
  static-put <iface> <4|6>        (JSON binding on stdin)
  static-del <iface> <4|6> <id>
  lease-del <iface> <ip>`)
		return 2
	}
	apiKey := *key
	if apiKey == "" && *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		apiKey = strings.TrimSpace(string(data))
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", *socket)
		},
	}}

	do := func(method, path string, body io.Reader) int {
		req, err := http.NewRequest(method, "http://bridgedhcp"+path, body)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		fmt.Println(strings.TrimSpace(string(out)))
		if resp.StatusCode >= 400 {
			return 1
		}
		return 0
	}

	cmd := rest[0]
	switch {
	case cmd == "status" && len(rest) == 1:
		return do("GET", "/v1/status", nil)
	case cmd == "leases" && len(rest) == 3:
		return do("GET", "/v1/ifaces/"+rest[1]+"/leases/"+rest[2], nil)
	case cmd == "statics-replace" && len(rest) == 3:
		return do("PUT", "/v1/ifaces/"+rest[1]+"/statics/"+rest[2], os.Stdin)
	case cmd == "static-put" && len(rest) == 3:
		return do("POST", "/v1/ifaces/"+rest[1]+"/statics/"+rest[2], os.Stdin)
	case cmd == "static-del" && len(rest) == 4:
		return do("DELETE", "/v1/ifaces/"+rest[1]+"/statics/"+rest[2]+"/"+rest[3], nil)
	case cmd == "lease-del" && len(rest) == 3:
		return do("DELETE", "/v1/ifaces/"+rest[1]+"/leases/"+rest[2], nil)
	}
	fmt.Fprintln(os.Stderr, "unknown command; run without arguments for usage")
	return 2
}
