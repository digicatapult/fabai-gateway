package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testModel      = "fabai-chat"
	protectedHost  = "protected.fabai.internal"
	kioskOrigin    = "https://kiosk.fabai.internal"
	documentBody   = `{"format":"https://tinfoil.sh/predicate/attestation/v3","body":"synthetic"}`
	platformHeader = "Tinfoil-Pt"
)

// syncBuffer is a log destination that tests can read while handlers write.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// replica is a stand-in for a cvmimage replica's TLS port. It records what
// reaches it.
type replica struct {
	server   *httptest.Server
	handler  http.Handler
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
	conns    atomic.Int64
	closed   atomic.Int64
}

func newReplica(t *testing.T, handler http.Handler, certs ...tls.Certificate) *replica {
	t.Helper()
	r := &replica{handler: handler}
	r.server = httptest.NewUnstartedServer(http.HandlerFunc(r.serve))
	r.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			r.conns.Add(1)
		case http.StateClosed, http.StateHijacked:
			r.closed.Add(1)
		}
	}
	if len(certs) > 0 {
		r.server.TLS = &tls.Config{Certificates: certs}
	}
	r.server.StartTLS()
	t.Cleanup(r.server.Close)
	return r
}

func (r *replica) serve(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.requests = append(r.requests, req)
	r.bodies = append(r.bodies, body)
	r.mu.Unlock()
	if r.handler != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
		r.handler.ServeHTTP(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(platformHeader, "sev-snp")
	_, _ = io.WriteString(w, documentBody)
}

func (r *replica) addr(t *testing.T) netip.AddrPort {
	t.Helper()
	return netip.MustParseAddrPort(r.server.Listener.Addr().String())
}

func (r *replica) received() ([]*http.Request, [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*http.Request(nil), r.requests...), append([][]byte(nil), r.bodies...)
}

func tableFor(t *testing.T, upstream netip.AddrPort) Table {
	t.Helper()
	table, err := ParseTable(fmt.Appendf(nil, `{
		"models": {%q: {"repo": "digicatapult/fabai-demo", "hosts": [%q]}},
		"hosts": {%q: {"upstream": %q}}
	}`, testModel, protectedHost, protectedHost, upstream))
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// gatewayFor serves a Gateway for one replica over plain HTTP; the client
// listener's TLS is tested on its own.
func gatewayFor(t *testing.T, r *replica) (*httptest.Server, *Routes, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	routes, err := NewRoutes(tableFor(t, r.addr(t)), log)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(routes, []string{kioskOrigin}, log))
	t.Cleanup(server.Close)
	return server, routes, logs
}

// testClient neither follows redirects nor asks for compression, so tests
// see exactly what the gateway returns.
var testClient = &http.Client{
	Transport:     &http.Transport{DisableCompression: true},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func send(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := testClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func newRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func sealedRequest(t *testing.T, base string, body io.Reader) *http.Request {
	t.Helper()
	req := newRequest(t, http.MethodPost, base+"/v1/chat/completions", body)
	req.Header.Set(sealHeader, protectedHost)
	req.Header.Set(modelHeader, testModel)
	return req
}

func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// selfSigned returns a certificate for host valid between notBefore and
// notAfter.
func selfSigned(t *testing.T, host string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
