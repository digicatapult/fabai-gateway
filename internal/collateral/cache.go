// Package collateral is the offline collateral service for cvmimage's
// nonce attestation, and the prep tool that fills its cache from AMD's Key
// Distribution Service (KDS). The service is untrusted: clients check every
// certificate and signature it supplies.
package collateral

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
)

// Cache file names.
const (
	VCEKFile      = "vcek.der"
	CertChainFile = "cert_chain.pem"
	CRLFile       = "crl.der"
	ManifestFile  = "manifest.json"

	manifestVersion = 1
)

// Manifest records what the cache holds and what it is for.
type Manifest struct {
	Version       int               `json:"version"`
	Product       string            `json:"product"`
	ChipID        string            `json:"chip_id"`
	ReportedTCB   string            `json:"reported_tcb"`
	CRLNextUpdate time.Time         `json:"crl_next_update"`
	Files         map[string]string `json:"files"`
}

// Cache is a validated collateral cache.
type Cache struct {
	Manifest   Manifest
	Collateral amd.Collateral
	ChipID     [64]byte
	TCB        amd.TCB
}

// LoadCache reads the cache in dir and validates it at now against roots:
// the files match the manifest, the chain and CRL check out, the CRL is
// current, and the VCEK is for the manifest's chip and TCB.
func LoadCache(dir string, roots amd.Roots, now time.Time) (*Cache, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no collateral cache in %s: run fabai-collateral prep", dir)
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	files := map[string]*[]byte{}
	c := &Cache{Manifest: m}
	files[VCEKFile], files[CertChainFile], files[CRLFile] = &c.Collateral.VCEKDER, &c.Collateral.CertChainPEM, &c.Collateral.CRLDER
	if len(m.Files) != len(files) {
		return nil, fmt.Errorf("%s lists %d files, want %d", ManifestFile, len(m.Files), len(files))
	}
	for name, out := range files {
		if *out, err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(*out); hex.EncodeToString(sum[:]) != m.Files[name] {
			return nil, fmt.Errorf("%s doesn't match its SHA-256 in %s", name, ManifestFile)
		}
	}
	if err := c.validate(roots, now); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cache) validate(roots amd.Roots, now time.Time) error {
	m := c.Manifest
	if m.Version != manifestVersion {
		return fmt.Errorf("%s version %d, want %d", ManifestFile, m.Version, manifestVersion)
	}
	chipID, err := ParseChipID(m.ChipID)
	if err != nil {
		return fmt.Errorf("%s: %w", ManifestFile, err)
	}
	raw, err := ParseTCB(m.ReportedTCB)
	if err != nil {
		return fmt.Errorf("%s: %w", ManifestFile, err)
	}
	tcb, err := amd.DecomposeTCB(m.Product, raw)
	if err != nil {
		return fmt.Errorf("%s: %w", ManifestFile, err)
	}
	checked, err := amd.Check(roots, m.Product, c.Collateral, now)
	if err != nil {
		return err
	}
	if want := amd.HardwareID(m.Product, chipID); !bytes.Equal(checked.HardwareID, want) {
		return fmt.Errorf("the cached VCEK is for chip %x, but the configured chip ID is %x", checked.HardwareID, want)
	}
	if checked.TCB != tcb {
		return fmt.Errorf("the cached VCEK is for TCB %s, but the configured TCB is %s", checked.TCB, tcb)
	}
	if !checked.NextUpdate.Equal(m.CRLNextUpdate) {
		return fmt.Errorf("the CRL's nextUpdate is %s, but %s says %s", checked.NextUpdate.Format(time.RFC3339), ManifestFile, m.CRLNextUpdate.Format(time.RFC3339))
	}
	c.ChipID, c.TCB = chipID, tcb
	return nil
}

// ParseChipID reads a 64-byte chip ID in hex.
func ParseChipID(s string) ([64]byte, error) {
	var id [64]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, fmt.Errorf("chip ID %q isn't 128 hex digits", s)
	}
	copy(id[:], b)
	return id, nil
}

// ParseTCB reads a raw REPORTED_TCB, written as 0x followed by hex digits.
func ParseTCB(s string) (uint64, error) {
	if len(s) < 3 || s[:2] != "0x" {
		return 0, fmt.Errorf("TCB %q isn't 0x followed by hex digits", s)
	}
	v, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("TCB %q isn't 0x followed by hex digits", s)
	}
	return v, nil
}

// FormatTCB writes a raw REPORTED_TCB as ParseTCB reads it.
func FormatTCB(v uint64) string { return fmt.Sprintf("0x%016x", v) }

// WriteCache writes collateral and its manifest to dir. Each file is written
// to a temporary name and renamed, and the manifest goes last, so a reader
// never sees a manifest for files that aren't there yet.
func WriteCache(dir string, product string, chipID [64]byte, reportedTCB uint64, nextUpdate time.Time, col amd.Collateral) (Manifest, error) {
	m := Manifest{
		Version: manifestVersion, Product: product, ChipID: hex.EncodeToString(chipID[:]),
		ReportedTCB: FormatTCB(reportedTCB), CRLNextUpdate: nextUpdate.UTC(), Files: map[string]string{},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Manifest{}, err
	}
	for name, data := range map[string][]byte{VCEKFile: col.VCEKDER, CertChainFile: col.CertChainPEM, CRLFile: col.CRLDER} {
		sum := sha256.Sum256(data)
		m.Files[name] = hex.EncodeToString(sum[:])
		if err := writeFileAtomic(filepath.Join(dir, name), data); err != nil {
			return Manifest{}, err
		}
	}
	data, err := json.Marshal(m, json.Deterministic(true))
	if err != nil {
		return Manifest{}, err
	}
	return m, writeFileAtomic(filepath.Join(dir, ManifestFile), append(data, '\n'))
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
