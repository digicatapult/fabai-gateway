package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	clientHandshakeTimeout = 10 * time.Second
	maxAcceptBackoff       = time.Second
)

// ClientTLSConfig returns the client listener's TLS settings: TLS 1.3 only,
// with HTTP/2 and HTTP/1.1.
func ClientTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

// handshakeListener completes each connection's TLS handshake before
// http.Server sees it. http.Server answers a plain-HTTP request on a TLS
// port with a 400; here such a connection, like any failed handshake, is
// closed without a response.
type handshakeListener struct {
	inner     net.Listener
	config    *tls.Config
	conns     chan net.Conn
	done      chan struct{}
	failed    chan struct{}
	acceptErr error
	closeOnce sync.Once
}

// ListenTLS returns a listener whose connections have completed a TLS
// handshake with config.
func ListenTLS(inner net.Listener, config *tls.Config) net.Listener {
	l := &handshakeListener{
		inner:  inner,
		config: config,
		conns:  make(chan net.Conn),
		done:   make(chan struct{}),
		failed: make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *handshakeListener) acceptLoop() {
	backoff := 5 * time.Millisecond
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.acceptErr = err
				close(l.failed)
				return
			}
			select {
			case <-time.After(backoff):
			case <-l.done:
				return
			}
			backoff = min(2*backoff, maxAcceptBackoff)
			continue
		}
		backoff = 5 * time.Millisecond
		go l.handshake(raw)
	}
}

func (l *handshakeListener) handshake(raw net.Conn) {
	conn := tls.Server(raw, l.config)
	ctx, cancel := context.WithTimeout(context.Background(), clientHandshakeTimeout)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return
	}
	select {
	case l.conns <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

func (l *handshakeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.failed:
		return nil, l.acceptErr
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handshakeListener) Close() error {
	err := net.ErrClosed
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.inner.Close()
	})
	return err
}

func (l *handshakeListener) Addr() net.Addr { return l.inner.Addr() }
