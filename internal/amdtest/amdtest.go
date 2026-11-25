// Package amdtest builds a synthetic AMD certificate chain, CRL and signed
// SEV-SNP reports, for tests of the collateral service and its prep tool.
// Its root is not AMD's; tests pass Roots to the code under test.
package amdtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
)

// Chain is a synthetic ARK, ASK and VCEK for one chip at one TCB.
type Chain struct {
	Product string
	ChipID  [64]byte
	TCB     amd.TCB
	ARK     *x509.Certificate
	ASK     *x509.Certificate
	VCEK    *x509.Certificate
	VCEKKey *ecdsa.PrivateKey
	arkKey  *rsa.PrivateKey
}

var (
	keysOnce       sync.Once
	arkKey, askKey *rsa.PrivateKey
	keysErr        error
)

// rsaKeys are generated once per test binary: 2048-bit RSA is slow.
func rsaKeys() (*rsa.PrivateKey, *rsa.PrivateKey, error) {
	keysOnce.Do(func() {
		if arkKey, keysErr = rsa.GenerateKey(rand.Reader, 2048); keysErr != nil {
			return
		}
		askKey, keysErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return arkKey, askKey, keysErr
}

// ChipID returns a chip ID whose bytes start at first.
func ChipID(first byte) [64]byte {
	var id [64]byte
	for i := range id {
		id[i] = first + byte(i)
	}
	return id
}

// New builds a chain whose VCEK is for chipID at tcb. Chains from New share
// their ARK and ASK keys.
func New(chipID [64]byte, tcb amd.TCB) (*Chain, error) {
	arkK, askK, err := rsaKeys()
	if err != nil {
		return nil, err
	}
	return newChain(chipID, tcb, arkK, askK)
}

// NewWithOwnKeys is New with freshly generated ARK and ASK keys, for a chain
// that mustn't verify against another.
func NewWithOwnKeys(chipID [64]byte, tcb amd.TCB) (*Chain, error) {
	arkK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	askK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return newChain(chipID, tcb, arkK, askK)
}

func newChain(chipID [64]byte, tcb amd.TCB, arkK, askK *rsa.PrivateKey) (*Chain, error) {
	vcekKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	created := time.Now().Add(-24 * time.Hour)
	ca := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: created, NotAfter: created.Add(25 * 365 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
			SignatureAlgorithm: x509.SHA384WithRSAPSS, SubjectKeyId: []byte(name),
		}
	}
	arkTemplate := ca(1, "ARK-"+tcb.Product)
	ark, err := create(arkTemplate, arkTemplate, &arkK.PublicKey, arkK)
	if err != nil {
		return nil, err
	}
	ask, err := create(ca(2, "SEV-"+tcb.Product), ark, &askK.PublicKey, arkK)
	if err != nil {
		return nil, err
	}
	vcekTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "SEV-VCEK"},
		NotBefore: created, NotAfter: created.Add(7 * 365 * 24 * time.Hour),
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		ExtraExtensions:    vcekExtensions(chipID, tcb),
	}
	vcek, err := create(vcekTemplate, ask, &vcekKey.PublicKey, askK)
	if err != nil {
		return nil, err
	}
	return &Chain{Product: tcb.Product, ChipID: chipID, TCB: tcb, ARK: ark, ASK: ask, VCEK: vcek, VCEKKey: vcekKey, arkKey: arkK}, nil
}

func create(template, parent *x509.Certificate, pub, priv any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func vcekExtensions(chipID [64]byte, tcb amd.TCB) []pkix.Extension {
	oid := func(arc ...int) asn1.ObjectIdentifier {
		return append(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1}, arc...)
	}
	integer := func(v uint8) []byte { b, _ := asn1.Marshal(int(v)); return b }
	name, _ := asn1.MarshalWithParams(tcb.Product+"-B0", "ia5")
	exts := []pkix.Extension{
		{Id: oid(2), Value: name},
		{Id: oid(3, 1), Value: integer(tcb.Bootloader)},
		{Id: oid(3, 2), Value: integer(tcb.TEE)},
		{Id: oid(3, 3), Value: integer(tcb.SNP)},
		{Id: oid(3, 8), Value: integer(tcb.Microcode)},
		{Id: oid(4), Value: amd.HardwareID(tcb.Product, chipID)},
	}
	if tcb.Product == amd.Turin {
		exts = append(exts, pkix.Extension{Id: oid(3, 9), Value: integer(tcb.FMC)})
	}
	return exts
}

// Roots trust the chain's ARK for its product.
func (c *Chain) Roots() amd.Roots { return amd.Roots{c.Product: c.ARK} }

// CertChainPEM is the ASK and then the ARK, as KDS serves them.
func (c *Chain) CertChainPEM() []byte {
	var b bytes.Buffer
	for _, cert := range []*x509.Certificate{c.ASK, c.ARK} {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return b.Bytes()
}

// CRL returns a CRL signed by the ARK, revoking the given serials.
func (c *Chain) CRL(thisUpdate, nextUpdate time.Time, revoked ...*big.Int) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, serial := range revoked {
		entries[i] = x509.RevocationListEntry{SerialNumber: serial, RevocationTime: thisUpdate}
	}
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
		RevokedCertificateEntries: entries, SignatureAlgorithm: x509.SHA384WithRSAPSS,
	}, c.ARK, c.arkKey)
}

// Collateral is the chain with a CRL valid from an hour ago until nextUpdate.
func (c *Chain) Collateral(nextUpdate time.Time) (amd.Collateral, error) {
	crl, err := c.CRL(time.Now().Add(-time.Hour), nextUpdate)
	if err != nil {
		return amd.Collateral{}, err
	}
	return amd.Collateral{VCEKDER: c.VCEK.Raw, CertChainPEM: c.CertChainPEM(), CRLDER: crl}, nil
}

// cpuidFamilyModel are the report's CPUID family and model for each product.
var cpuidFamilyModel = map[string][2]byte{amd.Milan: {0x19, 0x01}, amd.Genoa: {0x19, 0x11}, amd.Turin: {0x1A, 0x02}}

// Report returns a version 5 report for the chain's product and chip,
// carrying reportedTCB and signed by the VCEK.
func (c *Chain) Report(reportedTCB uint64) []byte {
	r := make([]byte, amd.ReportSize)
	binary.LittleEndian.PutUint32(r[0x00:], 5)
	binary.LittleEndian.PutUint32(r[0x34:], 1)
	binary.LittleEndian.PutUint64(r[0x180:], reportedTCB)
	cpuid := cpuidFamilyModel[c.Product]
	r[0x188], r[0x189] = cpuid[0], cpuid[1]
	copy(r[0x1A0:], c.ChipID[:])
	Sign(r, c.VCEKKey)
	return r
}

// Sign signs a report with key, overwriting its signature.
func Sign(report []byte, key *ecdsa.PrivateKey) {
	digest := sha512.Sum384(report[:0x2A0])
	rInt, sInt, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	clear(report[0x2A0:])
	putLE(report[0x2A0:0x2A0+72], rInt)
	putLE(report[0x2A0+72:0x2A0+144], sInt)
}

func putLE(dst []byte, v *big.Int) {
	be := v.FillBytes(make([]byte, len(dst)))
	slices.Reverse(be)
	copy(dst, be)
}
