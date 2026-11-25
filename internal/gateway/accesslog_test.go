package gateway

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// waitForLines waits for n log lines: each is written after its handler
// returns, which can be after the client has read the response.
func waitForLines(t *testing.T, logs *syncBuffer, n int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		out := logs.String()
		if got := strings.Count(out, "\n"); got >= n || time.Now().After(deadline) {
			if got != n {
				t.Fatalf("%d log lines, want %d:\n%s", got, n, out)
			}
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLogsCarryNoSecrets(t *testing.T) {
	const (
		canaryPrompt = "the canary sings at midnight"
		canaryToken  = "canary-bearer-token"
		canaryPrefix = "canary-cache-prefix"
		canaryNonce  = "cafebabe"
	)
	r := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "echo: ")
		_, _ = io.Copy(w, req.Body)
	}))
	gw, _, logs := gatewayFor(t, r)

	req := sealedRequest(t, gw.URL, strings.NewReader(canaryPrompt))
	req.Header.Set("Authorization", "Bearer "+canaryToken)
	req.Header.Set("X-Tinfoil-Cache-Prefix", canaryPrefix)
	if body := readAll(t, send(t, req).Body); !strings.Contains(string(body), canaryPrompt) {
		t.Fatalf("the request didn't reach the replica: %q", body)
	}
	resp := send(t, newRequest(t, http.MethodGet, gw.URL+relayPathV3+"?nonce="+canaryNonce+"&enclave="+protectedHost, nil))
	_, _ = io.Copy(io.Discard, resp.Body)

	out := waitForLines(t, logs, 2)
	for _, canary := range []string{canaryPrompt, canaryToken, canaryPrefix, canaryNonce} {
		if strings.Contains(out, canary) {
			t.Errorf("%q is in the logs:\n%s", canary, out)
		}
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	var sealed, relay map[string]any
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["path"] == relayPathV3 {
			relay = entry
		} else {
			sealed = entry
		}
	}
	upstream := r.addr(t).String()
	for key, want := range map[string]any{
		"msg": "request", "method": "POST", "path": "/v1/chat/completions", "status": 200.0,
		"bytes_in": float64(len(canaryPrompt)), "bytes_out": float64(len("echo: " + canaryPrompt)),
		"model": testModel, "seal": protectedHost, "upstream": upstream,
	} {
		if sealed[key] != want {
			t.Errorf("sealed request %s = %v, want %v", key, sealed[key], want)
		}
	}
	for _, key := range []string{"time", "duration_ms"} {
		if _, ok := sealed[key]; !ok {
			t.Errorf("sealed request has no %s", key)
		}
	}
	if relay["enclave"] != protectedHost || relay["path"] != relayPathV3 || relay["upstream"] != upstream {
		t.Errorf("relay: %v", relay)
	}
}
