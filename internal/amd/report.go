package amd

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// Offsets in an SEV-SNP attestation report (AMD SEV-SNP firmware ABI
// specification, publication 56860, table "ATTESTATION_REPORT Structure").
const (
	ReportSize = 0x4A0

	offVersion       = 0x00
	offSignatureAlgo = 0x34
	offKeyInfo       = 0x48
	offReportedTCB   = 0x180
	offCPUIDFamily   = 0x188
	offCPUIDModel    = 0x189
	offChipID        = 0x1A0
	offSignature     = 0x2A0

	chipIDSize        = 64
	turinSiliconIDLen = 8
	signatureCompSize = 72

	signatureAlgoECDSAP384SHA384 = 1
	signingKeyVCEK               = 0
)

// Report is the part of an SEV-SNP attestation report the collateral service
// needs: which chip and TCB its VCEK must be for.
type Report struct {
	raw         []byte
	Version     uint32
	Product     string // "" when the report doesn't say (version 2)
	ChipID      [chipIDSize]byte
	ReportedTCB uint64
	signedBy    uint32
}

// ParseReport reads a raw 1184-byte report. It checks the report's shape,
// not its signature.
func ParseReport(raw []byte) (*Report, error) {
	if len(raw) != ReportSize {
		return nil, fmt.Errorf("report is %d bytes, want %d", len(raw), ReportSize)
	}
	r := &Report{
		raw:         slices.Clone(raw),
		Version:     binary.LittleEndian.Uint32(raw[offVersion:]),
		ReportedTCB: binary.LittleEndian.Uint64(raw[offReportedTCB:]),
		signedBy:    (binary.LittleEndian.Uint32(raw[offKeyInfo:]) >> 2) & 0x7,
	}
	if r.Version < 2 {
		return nil, fmt.Errorf("report version %d isn't supported", r.Version)
	}
	if algo := binary.LittleEndian.Uint32(raw[offSignatureAlgo:]); algo != signatureAlgoECDSAP384SHA384 {
		return nil, fmt.Errorf("report signature algorithm %d isn't ECDSA P-384 with SHA-384", algo)
	}
	copy(r.ChipID[:], raw[offChipID:])
	if r.Version >= 3 {
		r.Product = productFromCPUID(raw[offCPUIDFamily], raw[offCPUIDModel])
	}
	return r, nil
}

// productFromCPUID maps the report's CPUID family and model to a product
// line, as AMD's KDS specification (publication 57230) does.
func productFromCPUID(family, model byte) string {
	switch {
	case family == 0x19 && model == 0x01:
		return Milan
	case family == 0x19 && model == 0x11:
		return Genoa
	case family == 0x1A && model>>4 <= 1:
		return Turin
	}
	return ""
}

// HardwareID is the chip ID as the product's VCEK carries it, and as KDS
// addresses it: Turin uses the 8-byte silicon ID that starts CHIP_ID.
func HardwareID(product string, chipID [chipIDSize]byte) []byte {
	if product == Turin {
		return slices.Clone(chipID[:turinSiliconIDLen])
	}
	return slices.Clone(chipID[:])
}

// VerifySignature checks that the report was signed by a VCEK, and by the
// VCEK whose public key is pub.
func (r *Report) VerifySignature(pub *ecdsa.PublicKey) error {
	if r.signedBy != signingKeyVCEK {
		return fmt.Errorf("report is signed by key type %d, not a VCEK", r.signedBy)
	}
	digest := sha512.Sum384(r.raw[:offSignature])
	sig := r.raw[offSignature:]
	rInt := littleEndianInt(sig[:signatureCompSize])
	sInt := littleEndianInt(sig[signatureCompSize : 2*signatureCompSize])
	if !ecdsa.Verify(pub, digest[:], rInt, sInt) {
		return errors.New("the VCEK doesn't verify the report's signature")
	}
	return nil
}

func littleEndianInt(b []byte) *big.Int {
	be := slices.Clone(b)
	slices.Reverse(be)
	return new(big.Int).SetBytes(be)
}
