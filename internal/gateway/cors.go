package gateway

import (
	"net/http"
	"slices"
	"strings"
)

// exposedHeaders are the response headers a browser client must read: the
// EHBP response nonce, the attestation document's platform type, the seal
// host a 412 names, and the retry hint.
const exposedHeaders = "Ehbp-Response-Nonce, Tinfoil-Pt, X-Tinfoil-Seal, Retry-After, Content-Type"

const allowedMethods = "GET, POST"

// cors answers preflights for the configured kiosk origins itself, and adds
// the response headers for them. A replica's own CORS headers never reach a
// browser: the proxy removes Origin on the way up and Access-Control-* on
// the way back.
type cors struct {
	origins []string
}

func (c cors) allowed(origin string) bool {
	return origin != "" && slices.Contains(c.origins, origin)
}

func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != ""
}

// preflight answers a CORS preflight without contacting a replica. Clients
// send Authorization explicitly, so credentials are never allowed.
func (c cors) preflight(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Add("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
	origin := r.Header.Get("Origin")
	if !c.allowed(origin) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", allowedMethods)
	if requested := requestedHeaders(r); requested != "" {
		h.Set("Access-Control-Allow-Headers", requested)
	}
	h.Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

// decorate adds the CORS response headers for an allowed origin.
func (c cors) decorate(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Add("Vary", "Origin")
	if origin := r.Header.Get("Origin"); c.allowed(origin) {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Expose-Headers", exposedHeaders)
	}
}

// requestedHeaders returns the preflight's requested headers, if every one is
// a valid header name. The configured origin is the kiosk's own bundle, so
// any header it asks for is allowed; the list isn't fixed because the
// client's HTTP library adds headers of its own.
func requestedHeaders(r *http.Request) string {
	var names []string
	for _, value := range r.Header.Values("Access-Control-Request-Headers") {
		for name := range strings.SplitSeq(value, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if !isToken(name) {
				return ""
			}
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

func isToken(s string) bool {
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return s != ""
}

// stripCORS removes a replica's CORS headers from its response.
func stripCORS(h http.Header) {
	for name := range h {
		if strings.HasPrefix(name, "Access-Control-") {
			delete(h, name)
		}
	}
}
