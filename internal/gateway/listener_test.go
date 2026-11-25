package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

const gatewayHost = "gateway.fabai.internal"

// serveTLS runs the gateway behind the client listener and returns its
// address and a pool trusting its certificate.
func serveTLS(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	cert := selfSigned(t, gatewayHost, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	r := newReplica(t, nil)
	log := slog.New(slog.DiscardHandler)
	routes, err := NewRoutes(tableFor(t, r.addr(t)), log)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	server := &http.Server{Handler: New(routes, nil, log), Protocols: &protocols}
	go func() { _ = server.Serve(ListenTLS(inner, ClientTLSConfig(cert))) }()
	t.Cleanup(func() { _ = server.Close() })
	return inner.Addr().String(), pool
}

func TestClientListener(t *testing.T) {
	addr, pool := serveTLS(t)
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			var protocols http.Protocols
			protocols.SetHTTP1(proto == "http/1.1")
			protocols.SetHTTP2(proto == "h2")
			client := &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: gatewayHost, NextProtos: []string{proto}},
				Protocols:       &protocols,
			}}
			resp, err := client.Get("https://" + addr + "/catalog")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.TLS.Version != tls.VersionTLS13 || resp.TLS.NegotiatedProtocol != proto {
				t.Errorf("%d, TLS %x, ALPN %q", resp.StatusCode, resp.TLS.Version, resp.TLS.NegotiatedProtocol)
			}
		})
	}
}

func TestClientListenerRefusesTLS12(t *testing.T) {
	addr, pool := serveTLS(t)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: gatewayHost, MaxVersion: tls.VersionTLS12})
	if err == nil {
		_ = conn.Close()
		t.Fatal("a TLS 1.2 handshake succeeded")
	}
}

func TestClientListenerRefusesPlainHTTP(t *testing.T) {
	addr, pool := serveTLS(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET /catalog HTTP/1.1\r\nHost: "+gatewayHost+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(conn); len(got) != 0 {
		t.Errorf("plain HTTP got %q (%v)", got, err)
	}

	// The listener still serves TLS clients afterwards.
	tlsConn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: gatewayHost})
	if err != nil {
		t.Fatal(err)
	}
	_ = tlsConn.Close()
}

func TestClientListenerUntrustedCertificate(t *testing.T) {
	addr, _ := serveTLS(t)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: x509.NewCertPool(), ServerName: gatewayHost})
	if err == nil {
		_ = conn.Close()
		t.Fatal("a client that doesn't trust the gateway's CA completed the handshake")
	}
}
