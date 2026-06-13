// Package api exposes the control API over a unix socket (no host port is
// consumed) guarded by a bearer key, so only holders of the key — not any
// local process that finds the socket — can mutate leases.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/HuJK/bridgedhcp/internal/server"
)

// Server is the HTTP-over-unix-socket control endpoint.
type Server struct {
	mgr  *server.Manager
	key  string
	ln   net.Listener
	http *http.Server
}

// New binds the unix socket (replacing a stale one) with mode 0600.
func New(mgr *server.Manager, socketPath, key string) (*Server, error) {
	if key == "" {
		return nil, fmt.Errorf("api key must not be empty")
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{mgr: mgr, key: key, ln: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("GET /v1/ifaces/{iface}/leases/{family}", s.handleLeases)
	mux.HandleFunc("PUT /v1/ifaces/{iface}/statics/{family}", s.handleReplaceStatics)
	mux.HandleFunc("POST /v1/ifaces/{iface}/statics/{family}", s.handlePutStatic)
	mux.HandleFunc("DELETE /v1/ifaces/{iface}/statics/{family}/{id}", s.handleDeleteStatic)
	mux.HandleFunc("DELETE /v1/ifaces/{iface}/leases/{ip}", s.handleDeleteLease)
	s.http = &http.Server{Handler: s.auth(mux)}
	go s.http.Serve(ln)
	return s, nil
}

func (s *Server) Close() {
	_ = s.http.Close()
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.key)) != 1 {
			httpError(w, http.StatusUnauthorized, "invalid api key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func familyOf(r *http.Request) (int, error) {
	switch r.PathValue("family") {
	case "4":
		return 4, nil
	case "6":
		return 6, nil
	}
	return 0, fmt.Errorf("family must be 4 or 6")
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"ifaces": s.mgr.Status()})
}

func (s *Server) handleLeases(w http.ResponseWriter, r *http.Request) {
	family, err := familyOf(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	leases, err := s.mgr.Leases(r.PathValue("iface"), family)
	if err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]any{"leases": leases})
}

func (s *Server) handleReplaceStatics(w http.ResponseWriter, r *http.Request) {
	family, err := familyOf(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	var body struct {
		Statics []server.StaticBinding `json:"statics"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.mgr.ReplaceStatics(r.PathValue("iface"), family, body.Statics); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handlePutStatic(w http.ResponseWriter, r *http.Request) {
	family, err := familyOf(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	var b server.StaticBinding
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.mgr.PutStatic(r.PathValue("iface"), family, b); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteStatic(w http.ResponseWriter, r *http.Request) {
	family, err := familyOf(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.mgr.DeleteStatic(r.PathValue("iface"), family, r.PathValue("id")); err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteLease(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad ip")
		return
	}
	if err := s.mgr.DeleteLease(r.PathValue("iface"), ip); err != nil {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}
