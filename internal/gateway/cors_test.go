package gateway

import (
	"net/http"
	"strings"
	"testing"
)

func preflight(t *testing.T, base, origin string) *http.Response {
	t.Helper()
	req := newRequest(t, http.MethodOptions, base+"/v1/chat/completions", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type, ehbp-encapsulated-key, x-tinfoil-seal, x-tinfoil-model")
	return send(t, req)
}

func TestPreflight(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, _ := gatewayFor(t, r)

	resp := preflight(t, gw.URL, kioskOrigin)
	h := resp.Header
	if resp.StatusCode != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != kioskOrigin {
		t.Errorf("kiosk origin: %d %v", resp.StatusCode, h)
	}
	if !strings.Contains(h.Get("Access-Control-Allow-Methods"), http.MethodPost) || !strings.Contains(h.Get("Access-Control-Allow-Headers"), "ehbp-encapsulated-key") {
		t.Errorf("kiosk origin: %v", h)
	}
	if h.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("credentials allowed")
	}

	resp = preflight(t, gw.URL, "https://attacker.example")
	if resp.StatusCode == http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("other origin: %d %v", resp.StatusCode, resp.Header)
	}
	if n := r.conns.Load(); n != 0 {
		t.Errorf("%d connections to the replica for preflights", n)
	}
}

func TestPreflightRefusesMalformedHeaderNames(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, _ := gatewayFor(t, r)
	req := newRequest(t, http.MethodOptions, gw.URL+"/v1/chat/completions", nil)
	req.Header.Set("Origin", kioskOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "authorization, bad header")
	if got := send(t, req).Header.Get("Access-Control-Allow-Headers"); got != "" {
		t.Errorf("allowed %q", got)
	}
}

func TestCORSResponses(t *testing.T) {
	r := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// The shim echoes any Origin, with credentials.
		w.Header().Set("Access-Control-Allow-Origin", "https://attacker.example")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Ehbp-Response-Nonce", "nonce")
	}))
	gw, _, _ := gatewayFor(t, r)

	req := sealedRequest(t, gw.URL, strings.NewReader("sealed"))
	req.Header.Set("Origin", kioskOrigin)
	resp := send(t, req)
	if got := resp.Header.Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != kioskOrigin {
		t.Errorf("Access-Control-Allow-Origin %q", got)
	}
	if resp.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("the replica's Access-Control-Allow-Credentials reached the client")
	}
	exposed := resp.Header.Get("Access-Control-Expose-Headers")
	for _, name := range []string{"Ehbp-Response-Nonce", "Tinfoil-Pt", "X-Tinfoil-Seal", "Retry-After", "Content-Type"} {
		if !strings.Contains(exposed, name) {
			t.Errorf("%s isn't exposed: %q", name, exposed)
		}
	}
	if reqs, _ := r.received(); reqs[0].Header.Get("Origin") != "" {
		t.Error("Origin reached the replica")
	}

	req = sealedRequest(t, gw.URL, strings.NewReader("sealed"))
	req.Header.Set("Origin", "https://attacker.example")
	if got := send(t, req).Header.Values("Access-Control-Allow-Origin"); len(got) != 0 {
		t.Errorf("other origin: Access-Control-Allow-Origin %q", got)
	}
}

func TestCORSOnGatewayAnswers(t *testing.T) {
	r := newReplica(t, nil)
	gw, _, _ := gatewayFor(t, r)
	req := sealedRequest(t, gw.URL, strings.NewReader("sealed"))
	req.Header.Set(sealHeader, "old.fabai.internal")
	req.Header.Set("Origin", kioskOrigin)
	resp := send(t, req)
	if resp.StatusCode != http.StatusPreconditionFailed || resp.Header.Get("Access-Control-Allow-Origin") != kioskOrigin || !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), sealHeader) {
		t.Errorf("412: %d %v", resp.StatusCode, resp.Header)
	}
}
