package gateway

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
)

const maxAdminBody = 4 << 10

// AdminHandler serves the host administrator's interface:
//
//	GET /routes               the current routing table
//	PUT /routes/{host}        {"upstream": "<ip>:<port>"} points a replica host at a new address
//
// It is served only on a Unix socket, never on the client listener.
func AdminHandler(routes *Routes) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /routes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, routes.Table())
	})
	mux.HandleFunc("PUT /routes/{host}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Upstream netip.AddrPort `json:"upstream"`
		}
		if err := json.UnmarshalRead(http.MaxBytesReader(w, r.Body, maxAdminBody), &body, json.RejectUnknownMembers(true)); err != nil {
			http.Error(w, fmt.Sprintf("want {\"upstream\": \"<ip>:<port>\"}: %v", err), http.StatusBadRequest)
			return
		}
		host := r.PathValue("host")
		switch err := routes.Swap(host, body.Upstream); {
		case errors.Is(err, ErrUnknownHost):
			http.NotFound(w, r)
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			writeJSON(w, http.StatusOK, routes.Table().Hosts[host])
		}
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

// ListenAdmin listens on a Unix socket at path, readable and writable by its
// owner and group only. A stale socket left by an earlier run is replaced;
// any other file at path is an error.
func ListenAdmin(path string, log *slog.Logger) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("admin socket %s: a file that isn't a socket is in the way", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing stale admin socket: %w", err)
		}
		log.Info("removed stale admin socket", "path", path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("admin socket permissions: %w", err)
	}
	return l, nil
}
