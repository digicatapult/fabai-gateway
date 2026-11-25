package gateway

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCatalogEndpoint(t *testing.T) {
	r := newReplica(t, nil)
	gw, routes, _ := gatewayFor(t, r)
	resp := send(t, newRequest(t, http.MethodGet, gw.URL+"/catalog", nil))
	want, _ := routes.Table().Catalog()
	if got := readAll(t, resp.Body); resp.StatusCode != http.StatusOK || !bytes.Equal(got, want) || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("%d %s: %s", resp.StatusCode, resp.Header.Get("Content-Type"), got)
	}
	if resp := send(t, newRequest(t, http.MethodPost, gw.URL+"/catalog", nil)); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /catalog: %d", resp.StatusCode)
	}
	if r.conns.Load() != 0 {
		t.Error("the catalog contacted a replica")
	}
}

func TestRelay(t *testing.T) {
	nonce := strings.Repeat("ab", 32)
	for _, path := range []string{relayPathV3, relayPath} {
		t.Run(path, func(t *testing.T) {
			r := newReplica(t, nil)
			gw, _, _ := gatewayFor(t, r)
			resp := send(t, newRequest(t, http.MethodGet, gw.URL+path+"?nonce="+nonce+"&enclave="+protectedHost, nil))
			body := readAll(t, resp.Body)
			if resp.StatusCode != http.StatusOK || string(body) != documentBody || resp.Header.Get(platformHeader) != "sev-snp" || resp.Header.Get("Content-Type") != "application/json" {
				t.Errorf("%d %v: %s", resp.StatusCode, resp.Header, body)
			}
			reqs, _ := r.received()
			if len(reqs) != 1 {
				t.Fatalf("%d requests reached the replica", len(reqs))
			}
			got := reqs[0]
			if got.URL.Path != relayPathV3 || got.URL.RawQuery != "nonce="+nonce {
				t.Errorf("replica got %s?%s", got.URL.Path, got.URL.RawQuery)
			}
			if got.Host != protectedHost || got.TLS.ServerName != protectedHost {
				t.Errorf("Host %q, SNI %q", got.Host, got.TLS.ServerName)
			}
		})
	}
}

func TestRelayStatusPassedThrough(t *testing.T) {
	r := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "attestation collateral unavailable", http.StatusServiceUnavailable)
	}))
	gw, _, _ := gatewayFor(t, r)
	resp := send(t, newRequest(t, http.MethodGet, gw.URL+relayPathV3+"?nonce=00&enclave="+protectedHost, nil))
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "60" {
		t.Errorf("%d %v", resp.StatusCode, resp.Header)
	}
}

func TestRelayRefuses(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, _ := gatewayFor(t, r)
	for query, want := range map[string]int{
		"nonce=00&enclave=169.254.169.254":                   http.StatusNotFound,
		"nonce=00&enclave=other.fabai.internal":              http.StatusNotFound,
		"nonce=00&enclave=" + strings.ToUpper(protectedHost): http.StatusNotFound,
		"nonce=00":                                                        http.StatusBadRequest,
		"enclave=" + protectedHost:                                        http.StatusBadRequest,
		"nonce=zz&enclave=" + protectedHost:                               http.StatusBadRequest,
		"nonce=00&nonce=01&enclave=" + protectedHost:                      http.StatusBadRequest,
		"nonce=00&enclave=" + protectedHost + "&enclave=x":                http.StatusBadRequest,
		"nonce=" + strings.Repeat("0", 130) + "&enclave=" + protectedHost: http.StatusBadRequest,
	} {
		if resp := send(t, newRequest(t, http.MethodGet, gw.URL+relayPathV3+"?"+query, nil)); resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", query, resp.StatusCode, want)
		}
	}
	if resp := send(t, newRequest(t, http.MethodPost, gw.URL+relayPathV3+"?nonce=00&enclave="+protectedHost, nil)); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	if n := r.conns.Load(); n != 0 {
		t.Errorf("%d connections to the replica", n)
	}
}

func TestSealRouting(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, _ := gatewayFor(t, r)

	req := sealedRequest(t, gw.URL, strings.NewReader("sealed"))
	req.Header.Del(sealHeader)
	if resp := send(t, req); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no seal: %d", resp.StatusCode)
	}

	req = sealedRequest(t, gw.URL, strings.NewReader("sealed"))
	req.Header.Set(modelHeader, "other-model")
	if resp := send(t, req); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown model: %d", resp.StatusCode)
	}

	req = sealedRequest(t, gw.URL, strings.NewReader("sealed"))
	req.Header.Set(sealHeader, "old.fabai.internal")
	if resp := send(t, req); resp.StatusCode != http.StatusPreconditionFailed || resp.Header.Get(sealHeader) != protectedHost {
		t.Errorf("stale seal: %d, %s %q", resp.StatusCode, sealHeader, resp.Header.Get(sealHeader))
	}
	if n := r.conns.Load(); n != 0 {
		t.Fatalf("%d connections to the replica before a routable request", n)
	}

	if resp := send(t, sealedRequest(t, gw.URL, strings.NewReader("sealed"))); resp.StatusCode != http.StatusOK {
		t.Errorf("routable: %d", resp.StatusCode)
	}
	reqs, bodies := r.received()
	if len(reqs) != 1 || reqs[0].URL.Path != "/v1/chat/completions" || string(bodies[0]) != "sealed" || reqs[0].Host != protectedHost {
		t.Errorf("replica got %d requests", len(reqs))
	}
}

func TestHeaders(t *testing.T) {
	r := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Ehbp-Response-Nonce", "response-nonce")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("\x1f\x8b not really gzip"))
	}))
	gw, _, _ := gatewayFor(t, r)
	req := sealedRequest(t, gw.URL, strings.NewReader("sealed"))
	for name, value := range map[string]string{
		"Authorization":          "Bearer key",
		"Ehbp-Encapsulated-Key":  "encapsulated",
		"X-Tinfoil-Cache-Prefix": "prefix",
		"Content-Type":           "application/json",
		"Connection":             "X-Hop",
		"X-Hop":                  "hop-by-hop",
		"Origin":                 kioskOrigin,
	} {
		req.Header.Set(name, value)
	}
	resp := send(t, req)
	if body := readAll(t, resp.Body); string(body) != "\x1f\x8b not really gzip" || resp.Header.Get("Ehbp-Response-Nonce") != "response-nonce" {
		t.Errorf("response %q, headers %v", body, resp.Header)
	}
	reqs, _ := r.received()
	got := reqs[0].Header
	for _, name := range []string{"Authorization", "Ehbp-Encapsulated-Key", sealHeader, modelHeader, "X-Tinfoil-Cache-Prefix", "Content-Type"} {
		if got.Get(name) != req.Header.Get(name) {
			t.Errorf("%s: replica got %q, sent %q", name, got.Get(name), req.Header.Get(name))
		}
	}
	for _, name := range []string{"X-Hop", "Origin", "X-Forwarded-For", "Forwarded", "Accept-Encoding"} {
		if got.Get(name) != "" {
			t.Errorf("replica got %s: %q", name, got.Get(name))
		}
	}
}

func TestRefusedProtocols(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, _ := gatewayFor(t, r)
	req := sealedRequest(t, gw.URL, nil)
	req.Method = http.MethodGet
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if resp := send(t, req); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("websocket: %d", resp.StatusCode)
	}
	req = sealedRequest(t, gw.URL, nil)
	req.Method = http.MethodConnect
	if resp := send(t, req); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("CONNECT: %d", resp.StatusCode)
	}
	if n := r.conns.Load(); n != 0 {
		t.Errorf("%d connections to the replica", n)
	}
}

func TestRedirects(t *testing.T) {
	r := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "https://elsewhere.example/", http.StatusFound)
	}))
	gw, _, _ := gatewayFor(t, r)
	resp := send(t, sealedRequest(t, gw.URL, strings.NewReader("sealed")))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://elsewhere.example/" {
		t.Errorf("%d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if reqs, _ := r.received(); len(reqs) != 1 {
		t.Errorf("the replica got %d requests", len(reqs))
	}

	// Paths that http.ServeMux would redirect reach the replica unchanged.
	for _, path := range []string{"//v1/chat/completions", "/v1/../v1/chat", "/v1/chat/"} {
		req := sealedRequest(t, gw.URL, nil)
		req.URL.Path, req.URL.RawPath = path, ""
		if resp := send(t, req); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://elsewhere.example/" {
			t.Errorf("%s: %d %q", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestAdminPathNotOnClientPort(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, _ := gatewayFor(t, r)
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		for _, path := range []string{"/routes", "/routes/" + protectedHost} {
			req := sealedRequest(t, gw.URL, strings.NewReader(`{"upstream":"127.0.0.1:1"}`))
			req.Method = method
			req.URL.Path = path
			if resp := send(t, req); resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s: %d", method, path, resp.StatusCode)
			}
		}
	}
}

func TestExpiredReplicaCertificate(t *testing.T) {
	cert := selfSigned(t, protectedHost, time.Now().Add(-3*time.Hour), time.Now().Add(-2*time.Hour))
	r := newReplica(t, nil, cert)
	gw, _, _ := gatewayFor(t, r)
	resp := send(t, newRequest(t, http.MethodGet, gw.URL+relayPathV3+"?nonce=00&enclave="+protectedHost, nil))
	if body := readAll(t, resp.Body); resp.StatusCode != http.StatusOK || string(body) != documentBody {
		t.Errorf("%d: %s", resp.StatusCode, body)
	}
}

func TestUnreachableReplica(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, logs := gatewayFor(t, r)
	r.server.Close()
	resp := send(t, newRequest(t, http.MethodGet, gw.URL+relayPathV3+"?nonce=00&enclave="+protectedHost, nil))
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("%d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if !strings.Contains(logs.String(), "upstream request failed") {
		t.Errorf("logs:\n%s", logs)
	}
}
