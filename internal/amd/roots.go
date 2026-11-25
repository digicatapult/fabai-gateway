// Package amd reads AMD SEV-SNP attestation reports and checks AMD's
// certificates for the collateral service and its prep tool, with the
// standard library only. Nothing here is the trust decision: clients check
// the same chain with fabai-attestation-verifier. These checks catch a bad
// cache before a client sees it.
package amd

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"maps"
)

// Product lines, as AMD's Key Distribution Service names them.
const (
	Milan = "Milan"
	Genoa = "Genoa"
	Turin = "Turin"
)

// The AMD root keys (ARK), byte-equal to the roots that
// fabai-attestation-verifier pins (its internal/amd/roots), which were
// fetched from KDS /vcek/v1/<product>/cert_chain.
var (
	//go:embed roots/ark_milan.pem
	arkMilanPEM []byte
	//go:embed roots/ark_genoa.pem
	arkGenoaPEM []byte
	//go:embed roots/ark_turin.pem
	arkTurinPEM []byte
)

// pinnedARKSHA256 holds the SHA-256 of each ARK's DER encoding, the same
// values fabai-attestation-verifier pins.
var pinnedARKSHA256 = map[string]string{
	Milan: "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
	Genoa: "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
	Turin: "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
}

// Roots maps a product line to its ARK.
type Roots map[string]*x509.Certificate

var pinnedRoots = mustLoadRoots()

// PinnedRoots returns AMD's ARKs. Tests pass synthetic roots to Check
// instead.
func PinnedRoots() Roots { return maps.Clone(pinnedRoots) }

func mustLoadRoots() Roots {
	roots := make(Roots, 3)
	for product, pemBytes := range map[string][]byte{Milan: arkMilanPEM, Genoa: arkGenoaPEM, Turin: arkTurinPEM} {
		cert, err := parsePinnedARK(product, pemBytes)
		if err != nil {
			panic(err)
		}
		roots[product] = cert
	}
	return roots
}

func parsePinnedARK(product string, pemBytes []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("pinned ARK for %s isn't one PEM certificate", product)
	}
	digest := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(digest[:]) != pinnedARKSHA256[product] {
		return nil, fmt.Errorf("pinned ARK for %s has SHA-256 %x, want %s", product, digest, pinnedARKSHA256[product])
	}
	return x509.ParseCertificate(block.Bytes)
}

// IsProduct reports whether name is a product line this package knows.
func IsProduct(name string) bool {
	_, ok := pinnedARKSHA256[name]
	return ok
}
