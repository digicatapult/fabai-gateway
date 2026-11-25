package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	relayPath            = "/.well-known/tinfoil-attestation"
	relayPathV3          = "/.well-known/tinfoil-attestation/v3"
	catalogPath          = "/catalog"
	adminPath            = "/routes"
	sealHeader           = "X-Tinfoil-Seal"
	modelHeader          = "X-Tinfoil-Model"
	maxNonceHexLength    = 128
	upstreamErrorMessage = "upstream unavailable"
)

// Gateway is the client-facing handler.
type Gateway struct {
	routes  *Routes
	cors    cors
	proxy   *httputil.ReverseProxy
	handler http.Handler
}

// New returns a Gateway that routes by routes, answers CORS preflights for
// origins, and logs each request to log.
func New(routes *Routes, origins []string, log *slog.Logger) *Gateway {
	g := &Gateway{routes: routes, cors: cors{origins: origins}}
	g.proxy = newProxy(log)
	g.handler = accessLog(log, http.HandlerFunc(g.serve))
	return g
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.handler.ServeHTTP(w, r)
}

// serve dispatches on the exact path. It doesn't use http.ServeMux, which
// answers some paths with redirects; the gateway never issues one.
func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	if isPreflight(r) {
		g.cors.preflight(w, r)
		return
	}
	g.cors.decorate(w, r)
	switch {
	case r.Method == http.MethodConnect:
		http.Error(w, "CONNECT is not supported", http.StatusMethodNotAllowed)
	case r.Header.Get("Upgrade") != "":
		http.Error(w, "protocol upgrades are not supported", http.StatusBadRequest)
	case r.URL.Path == catalogPath:
		g.catalog(w, r)
	case r.URL.Path == relayPath || r.URL.Path == relayPathV3:
		g.relay(w, r)
	case r.URL.Path == adminPath || strings.HasPrefix(r.URL.Path, adminPath+"/"):
		http.NotFound(w, r)
	default:
		g.sealed(w, r)
	}
}

func (g *Gateway) catalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(g.routes.snapshot().catalog)
}

// relay forwards an attestation request to the replica named by enclave,
// as /v3?nonce=<hex>: the shim refuses any other query parameter.
func (g *Gateway) relay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	enclaves, nonces := query["enclave"], query["nonce"]
	if len(enclaves) != 1 || len(nonces) != 1 || !isHexNonce(nonces[0]) {
		http.Error(w, "want exactly one enclave and one hex nonce", http.StatusBadRequest)
		return
	}
	info := infoFrom(r.Context())
	info.enclave = enclaves[0]
	u, ok := g.routes.snapshot().upstream(enclaves[0])
	if !ok {
		http.NotFound(w, r)
		return
	}
	info.upstream = u
	out := r.Clone(r.Context())
	out.URL.Path, out.URL.RawPath = relayPathV3, ""
	out.URL.RawQuery = url.Values{"nonce": nonces}.Encode()
	g.proxy.ServeHTTP(w, out)
}

// sealed routes a request by its X-Tinfoil-Seal header.
func (g *Gateway) sealed(w http.ResponseWriter, r *http.Request) {
	info := infoFrom(r.Context())
	info.seal = r.Header.Get(sealHeader)
	info.model = r.Header.Get(modelHeader)
	if info.seal == "" {
		http.Error(w, "missing "+sealHeader, http.StatusBadRequest)
		return
	}
	s := g.routes.snapshot()
	hosts, served := s.route(info.model, info.seal)
	if hosts == nil {
		http.NotFound(w, r)
		return
	}
	if !served {
		w.Header().Set(sealHeader, hosts[0])
		http.Error(w, "the sealed host doesn't serve this model", http.StatusPreconditionFailed)
		return
	}
	info.upstream, _ = s.upstream(info.seal)
	g.proxy.ServeHTTP(w, r)
}

func isHexNonce(s string) bool {
	if s == "" || len(s) > maxNonceHexLength {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
