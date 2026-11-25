// Package gateway is an untrusted HTTPS gateway between gateway clients and
// cvmimage inference replicas. It serves the catalog, relays attestation
// requests, and routes each sealed request to the replica named in its
// X-Tinfoil-Seal header. It holds no key that can open a request or a
// response: clients verify each replica themselves and seal each request body
// to that replica's attested key.
package gateway

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Table is the routing table: the models the gateway offers, the replica
// hosts that serve each one, and the address each replica host is reached at.
type Table struct {
	Models map[string]Model `json:"models"`
	Hosts  map[string]Host  `json:"hosts"`
}

// Model is one catalog entry.
type Model struct {
	Repo  string   `json:"repo"`
	Hosts []string `json:"hosts"`
}

// Host is a replica host's upstream address, an IP literal and port, so that
// routing never needs DNS.
type Host struct {
	Upstream netip.AddrPort `json:"upstream"`
}

// hostName matches a lowercase DNS name. Replica host names are compared
// byte for byte with the enclave parameter and the X-Tinfoil-Seal header.
var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// LoadTable reads and validates a routing table from a JSON file.
func LoadTable(path string) (Table, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Table{}, fmt.Errorf("reading routing table: %w", err)
	}
	return ParseTable(data)
}

// ParseTable decodes a routing table strictly, refusing unknown and repeated
// members, and validates it.
func ParseTable(data []byte) (Table, error) {
	var t Table
	if err := json.Unmarshal(data, &t, json.RejectUnknownMembers(true)); err != nil {
		return Table{}, fmt.Errorf("routing table: %w", err)
	}
	if err := t.validate(); err != nil {
		return Table{}, fmt.Errorf("routing table: %w", err)
	}
	return t, nil
}

func (t Table) validate() error {
	if len(t.Models) == 0 {
		return errors.New("no models")
	}
	for host, h := range t.Hosts {
		if len(host) > 253 || !hostName.MatchString(host) {
			return fmt.Errorf("host %q isn't a lowercase DNS name", host)
		}
		if err := validUpstream(h.Upstream); err != nil {
			return fmt.Errorf("host %q: %w", host, err)
		}
	}
	served := map[string]bool{}
	for name, m := range t.Models {
		if strings.TrimSpace(name) == "" {
			return errors.New("a model has an empty name")
		}
		if strings.TrimSpace(m.Repo) == "" {
			return fmt.Errorf("model %q has no repo", name)
		}
		if len(m.Hosts) == 0 {
			return fmt.Errorf("model %q has no hosts", name)
		}
		for i, host := range m.Hosts {
			if _, ok := t.Hosts[host]; !ok {
				return fmt.Errorf("model %q names host %q, which isn't in hosts", name, host)
			}
			if slices.Contains(m.Hosts[:i], host) {
				return fmt.Errorf("model %q names host %q twice", name, host)
			}
			served[host] = true
		}
	}
	for host := range t.Hosts {
		if !served[host] {
			return fmt.Errorf("host %q serves no model", host)
		}
	}
	return nil
}

func validUpstream(a netip.AddrPort) error {
	if !a.IsValid() || a.Port() == 0 || a.Addr().Zone() != "" {
		return fmt.Errorf("upstream %q isn't an IP address and port", a)
	}
	return nil
}

// Catalog returns the body of GET /catalog: each model's repo and hosts.
func (t Table) Catalog() ([]byte, error) {
	return json.Marshal(t.Models, json.Deterministic(true))
}

// withUpstream returns a copy of t with host's upstream replaced.
func (t Table) withUpstream(host string, upstream netip.AddrPort) Table {
	hosts := make(map[string]Host, len(t.Hosts))
	for name, h := range t.Hosts {
		hosts[name] = h
	}
	hosts[host] = Host{Upstream: upstream}
	return Table{Models: t.Models, Hosts: hosts}
}
