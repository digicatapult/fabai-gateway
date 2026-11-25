package gateway

import (
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func adminClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
}

func serveAdmin(t *testing.T, routes *Routes) *http.Client {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.sock")
	l, err := ListenAdmin(path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: AdminHandler(routes)}
	go func() { _ = server.Serve(l) }()
	t.Cleanup(func() { _ = server.Close() })
	return adminClient(path)
}

func adminDo(t *testing.T, client *http.Client, method, path, body string) (int, string) {
	t.Helper()
	req := newRequest(t, method, "http://admin"+path, strings.NewReader(body))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func TestAdminSwap(t *testing.T) {
	old := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "old") }))
	modified := newReplica(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "modified") }))
	gw, routes, _ := gatewayFor(t, old)
	admin := serveAdmin(t, routes)

	status, body := adminDo(t, admin, http.MethodGet, "/routes", "")
	var table Table
	if err := json.Unmarshal([]byte(body), &table); status != http.StatusOK || err != nil || table.Hosts[protectedHost].Upstream != old.addr(t) {
		t.Fatalf("GET /routes: %d %s %v", status, body, err)
	}

	status, body = adminDo(t, admin, http.MethodPut, "/routes/"+protectedHost, `{"upstream": "`+modified.addr(t).String()+`"}`)
	if status != http.StatusOK || !strings.Contains(body, modified.addr(t).String()) {
		t.Fatalf("PUT: %d %s", status, body)
	}
	if got := readAll(t, send(t, sealedRequest(t, gw.URL, nil)).Body); string(got) != "modified" {
		t.Errorf("after the swap: %q", got)
	}
}

func TestAdminRefuses(t *testing.T) {
	r := newReplica(t, nil)
	_, routes, _ := gatewayFor(t, r)
	admin := serveAdmin(t, routes)
	before := routes.Table()
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodPut, "/routes/other.fabai.internal", `{"upstream": "127.0.0.1:443"}`, http.StatusNotFound},
		{http.MethodPut, "/routes/" + protectedHost, `{"upstream": "replica.local:443"}`, http.StatusBadRequest},
		{http.MethodPut, "/routes/" + protectedHost, `{"upstream": "127.0.0.1:0"}`, http.StatusBadRequest},
		{http.MethodPut, "/routes/" + protectedHost, `{"upstream": "127.0.0.1:443", "extra": 1}`, http.StatusBadRequest},
		{http.MethodPut, "/routes/" + protectedHost, `{"upstream": "` + strings.Repeat("1", 5000) + `"}`, http.StatusBadRequest},
		{http.MethodPost, "/routes/" + protectedHost, `{"upstream": "127.0.0.1:443"}`, http.StatusMethodNotAllowed},
		{http.MethodGet, "/catalog", "", http.StatusNotFound},
	} {
		if status, body := adminDo(t, admin, tc.method, tc.path, tc.body); status != tc.want {
			t.Errorf("%s %s %s: %d %s", tc.method, tc.path, tc.body, status, body)
		}
	}
	if routes.Table().Hosts[protectedHost] != before.Hosts[protectedHost] {
		t.Error("a refused request changed the table")
	}
}

func TestListenAdmin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.sock")
	log := slog.New(slog.DiscardHandler)

	l, err := ListenAdmin(path, log)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o660 {
		t.Errorf("socket mode %o, want 660", perm)
	}

	// A socket left behind by a process that didn't clean up is replaced.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	l, err = ListenAdmin(path, log)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	_ = l.Close()

	other := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(other, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenAdmin(other, log); err == nil {
		t.Error("replaced a regular file")
	}
	if data, _ := os.ReadFile(other); string(data) != "keep me" {
		t.Error("the regular file was changed")
	}
}
