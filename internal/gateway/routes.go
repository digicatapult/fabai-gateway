package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	upstreamDialTimeout      = 10 * time.Second
	upstreamHandshakeTimeout = 10 * time.Second
	upstreamIdleTimeout      = 90 * time.Second
)

// ErrUnknownHost is returned for a replica host that isn't in the table.
var ErrUnknownHost = errors.New("unknown replica host")

// Routes holds the current routing table. Each request reads one snapshot,
// so a request that starts after a swap uses the new upstream from its first
// byte, and requests already in flight finish on the old one.
type Routes struct {
	current atomic.Pointer[snapshot]
	swapMu  sync.Mutex
	log     *slog.Logger
}

type snapshot struct {
	table     Table
	catalog   []byte
	upstreams map[string]*upstream
}

// upstream is the connection pool for one replica host at one address. A
// swap replaces it, so a pooled connection to the old address is never
// reused for the new one.
type upstream struct {
	host      string
	addr      netip.AddrPort
	transport *http.Transport
}

// NewRoutes returns Routes serving t.
func NewRoutes(t Table, log *slog.Logger) (*Routes, error) {
	s, err := newSnapshot(t, nil)
	if err != nil {
		return nil, err
	}
	r := &Routes{log: log}
	r.current.Store(s)
	return r, nil
}

func newSnapshot(t Table, reuse map[string]*upstream) (*snapshot, error) {
	catalog, err := t.Catalog()
	if err != nil {
		return nil, err
	}
	s := &snapshot{table: t, catalog: catalog, upstreams: make(map[string]*upstream, len(t.Hosts))}
	for host, h := range t.Hosts {
		if u := reuse[host]; u != nil && u.addr == h.Upstream {
			s.upstreams[host] = u
			continue
		}
		s.upstreams[host] = newUpstream(host, h.Upstream)
	}
	return s, nil
}

func newUpstream(host string, addr netip.AddrPort) *upstream {
	dialer := &net.Dialer{Timeout: upstreamDialTimeout}
	return &upstream{
		host: host,
		addr: addr,
		transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr.String())
			},
			// The replica's certificate isn't checked: in tls-mode
			// self-signed it expires an hour after boot, and nothing on this
			// hop is trusted. Clients seal each body to the replica's
			// attested key.
			TLSClientConfig:     &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: upstreamHandshakeTimeout,
			IdleConnTimeout:     upstreamIdleTimeout,
			// Bodies must reach the client byte for byte.
			DisableCompression: true,
		},
	}
}

// Table returns the current routing table.
func (r *Routes) Table() Table { return r.current.Load().table }

func (r *Routes) snapshot() *snapshot { return r.current.Load() }

// Swap points a replica host at a new upstream address. Requests that start
// after it returns use the new address; idle connections to the old address
// are closed.
func (r *Routes) Swap(host string, addr netip.AddrPort) error {
	if err := validUpstream(addr); err != nil {
		return err
	}
	r.swapMu.Lock()
	defer r.swapMu.Unlock()
	old := r.current.Load()
	prev, ok := old.table.Hosts[host]
	if !ok {
		return ErrUnknownHost
	}
	next, err := newSnapshot(old.table.withUpstream(host, addr), old.upstreams)
	if err != nil {
		return err
	}
	r.current.Store(next)
	if u := old.upstreams[host]; u != next.upstreams[host] {
		u.transport.CloseIdleConnections()
	}
	r.log.Info("route swapped", "host", host, "from", prev.Upstream.String(), "to", addr.String())
	return nil
}

// upstream returns the pool for a replica host, if the table has it.
func (s *snapshot) upstream(host string) (*upstream, bool) {
	u, ok := s.upstreams[host]
	return u, ok
}

// route resolves a sealed request. It returns the hosts serving model, and
// whether seal is one of them.
func (s *snapshot) route(model, seal string) (hosts []string, served bool) {
	m, ok := s.table.Models[model]
	if !ok {
		return nil, false
	}
	return m.Hosts, slices.Contains(m.Hosts, seal)
}
