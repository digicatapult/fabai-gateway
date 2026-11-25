package amd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// VCEK certificate extensions (AMD KDS specification, publication 57230).
var (
	oidProductName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 2}
	oidBlSPL       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 1}
	oidTeeSPL      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 2}
	oidSnpSPL      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 3}
	oidUcodeSPL    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 8}
	oidFmcSPL      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 9}
	oidHWID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 4}
)

// Collateral is a VCEK, its ASK-then-ARK chain and the product's CRL, as KDS
// serves them.
type Collateral struct {
	VCEKDER      []byte
	CertChainPEM []byte
	CRLDER       []byte
}

// Checked is what Check learnt about valid collateral.
type Checked struct {
	VCEK       *x509.Certificate
	HardwareID []byte
	TCB        TCB
	NextUpdate time.Time
}

// Check validates collateral for product at now: the chain ends in the
// product's root from roots, the ARK signs the ASK and the CRL, the ASK signs
// the VCEK, the CRL is current and revokes neither, and the VCEK is for
// product.
func Check(roots Roots, product string, c Collateral, now time.Time) (*Checked, error) {
	ark, ok := roots[product]
	if !ok {
		return nil, fmt.Errorf("no root for product %q", product)
	}
	ask, chainARK, err := parseChain(c.CertChainPEM)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(chainARK.Raw, ark.Raw) {
		return nil, fmt.Errorf("the chain's ARK isn't the pinned %s root", product)
	}
	if err := signs(ark, ask.SignatureAlgorithm, ask.RawTBSCertificate, ask.Signature); err != nil {
		return nil, fmt.Errorf("the ARK doesn't sign the ASK: %w", err)
	}
	vcek, err := x509.ParseCertificate(c.VCEKDER)
	if err != nil {
		return nil, fmt.Errorf("VCEK: %w", err)
	}
	if err := signs(ask, vcek.SignatureAlgorithm, vcek.RawTBSCertificate, vcek.Signature); err != nil {
		return nil, fmt.Errorf("the ASK doesn't sign the VCEK: %w", err)
	}
	if _, ok := vcek.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, errors.New("the VCEK's key isn't ECDSA")
	}
	crl, err := x509.ParseRevocationList(c.CRLDER)
	if err != nil {
		return nil, fmt.Errorf("CRL: %w", err)
	}
	if err := signs(ark, crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature); err != nil {
		return nil, fmt.Errorf("the ARK doesn't sign the CRL: %w", err)
	}
	if now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
		return nil, fmt.Errorf("the CRL isn't current: valid from %s until %s", crl.ThisUpdate.Format(time.RFC3339), crl.NextUpdate.Format(time.RFC3339))
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(ask.SerialNumber) == 0 || entry.SerialNumber.Cmp(vcek.SerialNumber) == 0 {
			return nil, fmt.Errorf("the CRL revokes serial %x", entry.SerialNumber)
		}
	}
	hwid, tcb, err := vcekIdentity(product, vcek)
	if err != nil {
		return nil, err
	}
	return &Checked{VCEK: vcek, HardwareID: hwid, TCB: tcb, NextUpdate: crl.NextUpdate}, nil
}

func parseChain(chainPEM []byte) (ask, ark *x509.Certificate, err error) {
	var certs []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, nil, errors.New("cert chain has trailing data")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("cert chain holds a %q block", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("cert chain: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) != 2 {
		return nil, nil, fmt.Errorf("cert chain holds %d certificates, want the ASK and the ARK", len(certs))
	}
	return certs[0], certs[1], nil
}

// signs checks a signature directly. AMD's ARK and ASK don't all carry the
// CA constraints that x509's CheckSignatureFrom insists on.
func signs(parent *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	return parent.CheckSignature(algo, signed, signature)
}

func vcekIdentity(product string, vcek *x509.Certificate) ([]byte, TCB, error) {
	exts := map[string][]byte{}
	for _, ext := range vcek.Extensions {
		exts[ext.Id.String()] = ext.Value
	}
	var name string
	if _, err := asn1.UnmarshalWithParams(exts[oidProductName.String()], &name, "ia5"); err != nil || !strings.HasPrefix(name, product+"-") && name != product {
		return nil, TCB{}, fmt.Errorf("the VCEK is for product %q, not %s", name, product)
	}
	spl := func(oid asn1.ObjectIdentifier) (uint8, error) {
		var v int
		if rest, err := asn1.Unmarshal(exts[oid.String()], &v); err != nil || len(rest) != 0 || v < 0 || v > 255 {
			return 0, fmt.Errorf("the VCEK's SPL extension %v is missing or malformed", oid)
		}
		return uint8(v), nil
	}
	tcb := TCB{Product: product}
	var err error
	for _, f := range []struct {
		oid asn1.ObjectIdentifier
		out *uint8
	}{{oidBlSPL, &tcb.Bootloader}, {oidTeeSPL, &tcb.TEE}, {oidSnpSPL, &tcb.SNP}, {oidUcodeSPL, &tcb.Microcode}} {
		if *f.out, err = spl(f.oid); err != nil {
			return nil, TCB{}, err
		}
	}
	if product == Turin {
		if tcb.FMC, err = spl(oidFmcSPL); err != nil {
			return nil, TCB{}, err
		}
	}
	hwid, err := hardwareIDExtension(product, exts[oidHWID.String()])
	if err != nil {
		return nil, TCB{}, err
	}
	return hwid, tcb, nil
}

// hardwareIDExtension reads the VCEK's hardware ID. KDS stores the raw
// bytes without an ASN.1 tag; a tagged OCTET STRING is accepted too.
func hardwareIDExtension(product string, value []byte) ([]byte, error) {
	size := chipIDSize
	if product == Turin {
		size = turinSiliconIDLen
	}
	if len(value) == size {
		return value, nil
	}
	var octets []byte
	if rest, err := asn1.Unmarshal(value, &octets); err == nil && len(rest) == 0 && len(octets) == size {
		return octets, nil
	}
	return nil, fmt.Errorf("the VCEK's hardware ID is missing or isn't %d bytes", size)
}

// KDS URLs for a product's VCEK, cert chain and CRL.
func VCEKURL(base, product string, hwid []byte, tcb TCB) string {
	return fmt.Sprintf("%s/vcek/v1/%s/%s?%s", base, product, hex.EncodeToString(hwid), tcb.Values().Encode())
}

func CertChainURL(base, product string) string {
	return fmt.Sprintf("%s/vcek/v1/%s/cert_chain", base, product)
}

func CRLURL(base, product string) string {
	return fmt.Sprintf("%s/vcek/v1/%s/crl", base, product)
}
