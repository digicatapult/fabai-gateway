package amd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
	"github.com/digicatapult/fabai-gateway/internal/amdtest"
)

// TestPinnedRootsMatchVerifier pins the embedded ARKs to the same SHA-256
// values as fabai-attestation-verifier's pinnedARKSHA256, so the service and
// the clients agree about which roots are AMD's.
func TestPinnedRootsMatchVerifier(t *testing.T) {
	want := map[string]string{
		amd.Milan: "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
		amd.Genoa: "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
		amd.Turin: "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
	}
	roots := amd.PinnedRoots()
	if len(roots) != len(want) {
		t.Fatalf("%d roots", len(roots))
	}
	for product, digest := range want {
		sum := sha256.Sum256(roots[product].Raw)
		if hex.EncodeToString(sum[:]) != digest || roots[product].Subject.CommonName != "ARK-"+product {
			t.Errorf("%s: SHA-256 %x, subject %q", product, sum, roots[product].Subject.CommonName)
		}
	}
}

func TestTCB(t *testing.T) {
	turin := amd.TCB{Product: amd.Turin, FMC: 1, Bootloader: 2, TEE: 3, SNP: 4, Microcode: 5}
	if got := turin.Uint64(); got != 0x0500000004030201 {
		t.Errorf("Turin raw 0x%016x", got)
	}
	genoa := amd.TCB{Product: amd.Genoa, Bootloader: 2, TEE: 3, SNP: 4, Microcode: 5}
	if got := genoa.Uint64(); got != 0x0504000000000302 {
		t.Errorf("Genoa raw 0x%016x", got)
	}
	for _, tcb := range []amd.TCB{turin, genoa} {
		back, err := amd.DecomposeTCB(tcb.Product, tcb.Uint64())
		if err != nil || back != tcb {
			t.Errorf("%s round trip: %+v, %v", tcb.Product, back, err)
		}
	}
	if got := turin.Values().Encode(); got != "blSPL=2&fmcSPL=1&snpSPL=4&teeSPL=3&ucodeSPL=5" {
		t.Errorf("Turin query %s", got)
	}
	if got := genoa.Values().Encode(); got != "blSPL=2&snpSPL=4&teeSPL=3&ucodeSPL=5" {
		t.Errorf("Genoa query %s", got)
	}
	if _, err := amd.DecomposeTCB("Naples", 0); err == nil {
		t.Error("decomposed an unknown product's TCB")
	}
}

func TestKDSURLs(t *testing.T) {
	tcb := amd.TCB{Product: amd.Turin, FMC: 1, Bootloader: 2, TEE: 3, SNP: 4, Microcode: 5}
	hwid := amd.HardwareID(amd.Turin, amdtest.ChipID(0xa0))
	if len(hwid) != 8 {
		t.Fatalf("Turin hardware ID is %d bytes", len(hwid))
	}
	if got := amd.VCEKURL("https://kds", amd.Turin, hwid, tcb); got != "https://kds/vcek/v1/Turin/a0a1a2a3a4a5a6a7?blSPL=2&fmcSPL=1&snpSPL=4&teeSPL=3&ucodeSPL=5" {
		t.Errorf("VCEK URL %s", got)
	}
	if got := len(amd.HardwareID(amd.Genoa, amdtest.ChipID(0))); got != 64 {
		t.Errorf("Genoa hardware ID is %d bytes", got)
	}
	if amd.CertChainURL("https://kds", amd.Genoa) != "https://kds/vcek/v1/Genoa/cert_chain" || amd.CRLURL("https://kds", amd.Genoa) != "https://kds/vcek/v1/Genoa/crl" {
		t.Error("cert chain or CRL URL")
	}
}

func newChain(t *testing.T, product string) *amdtest.Chain {
	t.Helper()
	tcb := amd.TCB{Product: product, Bootloader: 9, TEE: 0, SNP: 23, Microcode: 72}
	if product == amd.Turin {
		tcb.FMC = 1
	}
	c, err := amdtest.New(amdtest.ChipID(0x10), tcb)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseReport(t *testing.T) {
	for _, product := range []string{amd.Milan, amd.Genoa, amd.Turin} {
		c := newChain(t, product)
		r, err := amd.ParseReport(c.Report(c.TCB.Uint64()))
		if err != nil {
			t.Fatal(err)
		}
		if r.Product != product || r.ChipID != c.ChipID || r.ReportedTCB != c.TCB.Uint64() || r.Version != 5 {
			t.Errorf("%s: %+v", product, r)
		}
		if err := r.VerifySignature(&c.VCEKKey.PublicKey); err != nil {
			t.Errorf("%s: %v", product, err)
		}
	}
}

func TestParseReportRefuses(t *testing.T) {
	c := newChain(t, amd.Turin)
	good := c.Report(c.TCB.Uint64())
	for name, edit := range map[string]func([]byte) []byte{
		"short":         func(r []byte) []byte { return r[:100] },
		"version 1":     func(r []byte) []byte { binary.LittleEndian.PutUint32(r, 1); return r },
		"signature alg": func(r []byte) []byte { binary.LittleEndian.PutUint32(r[0x34:], 2); return r },
	} {
		if _, err := amd.ParseReport(edit(bytes.Clone(good))); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	v2 := bytes.Clone(good)
	binary.LittleEndian.PutUint32(v2, 2)
	if r, err := amd.ParseReport(v2); err != nil || r.Product != "" {
		t.Errorf("version 2: product %q, %v", r.Product, err)
	}
}

func TestVerifySignatureRefuses(t *testing.T) {
	c := newChain(t, amd.Turin)
	other := newChain(t, amd.Turin)
	report := c.Report(c.TCB.Uint64())

	tampered := bytes.Clone(report)
	tampered[0x90] ^= 1
	vlek := bytes.Clone(report)
	vlek[0x48] |= 1 << 2
	amdtest.Sign(vlek, c.VCEKKey)
	for name, tc := range map[string]struct {
		raw  []byte
		with *amdtest.Chain
	}{
		"tampered":  {tampered, c},
		"other key": {report, other},
		"VLEK":      {vlek, c},
	} {
		r, err := amd.ParseReport(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.VerifySignature(&tc.with.VCEKKey.PublicKey); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestCheck(t *testing.T) {
	for _, product := range []string{amd.Genoa, amd.Turin} {
		c := newChain(t, product)
		next := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Second)
		col, err := c.Collateral(next)
		if err != nil {
			t.Fatal(err)
		}
		got, err := amd.Check(c.Roots(), product, col, time.Now())
		if err != nil {
			t.Fatalf("%s: %v", product, err)
		}
		if !bytes.Equal(got.HardwareID, amd.HardwareID(product, c.ChipID)) || got.TCB != c.TCB || !got.NextUpdate.Equal(next) {
			t.Errorf("%s: %+v", product, got)
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	c := newChain(t, amd.Turin)
	other, err := amdtest.NewWithOwnKeys(c.ChipID, c.TCB)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good, err := c.Collateral(now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	crl := func(this, next time.Time) []byte {
		t.Helper()
		der, err := c.CRL(this, next)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	revokedVCEK, err := c.CRL(now.Add(-time.Hour), now.Add(time.Hour), c.VCEK.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	revokedASK, err := c.CRL(now.Add(-time.Hour), now.Add(time.Hour), c.ASK.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		roots   amd.Roots
		product string
		edit    func(*amd.Collateral)
		want    string
	}{
		"AMD's roots":  {roots: amd.PinnedRoots(), want: "isn't the pinned"},
		"no root":      {product: amd.Genoa, want: "no root"},
		"expired CRL":  {edit: func(col *amd.Collateral) { col.CRLDER = crl(now.Add(-2*time.Hour), now.Add(-time.Hour)) }, want: "isn't current"},
		"future CRL":   {edit: func(col *amd.Collateral) { col.CRLDER = crl(now.Add(time.Hour), now.Add(2*time.Hour)) }, want: "isn't current"},
		"revoked VCEK": {edit: func(col *amd.Collateral) { col.CRLDER = revokedVCEK }, want: "revokes"},
		"revoked ASK":  {edit: func(col *amd.Collateral) { col.CRLDER = revokedASK }, want: "revokes"},
		"other VCEK":   {edit: func(col *amd.Collateral) { col.VCEKDER = other.VCEK.Raw }, want: "doesn't sign the VCEK"},
		"other CRL":    {edit: func(col *amd.Collateral) { col.CRLDER, _ = other.CRL(now.Add(-time.Hour), now.Add(time.Hour)) }, want: "doesn't sign the CRL"},
		"one certificate": {edit: func(col *amd.Collateral) {
			col.CertChainPEM = col.CertChainPEM[:bytes.Index(col.CertChainPEM[1:], []byte("-----BEGIN"))+1]
		}, want: "holds 1"},
		"trailing data":    {edit: func(col *amd.Collateral) { col.CertChainPEM = append(bytes.Clone(col.CertChainPEM), "junk"...) }, want: "trailing"},
		"VCEK not DER":     {edit: func(col *amd.Collateral) { col.VCEKDER = []byte("not DER") }, want: "VCEK"},
		"CRL not DER":      {edit: func(col *amd.Collateral) { col.CRLDER = []byte("not DER") }, want: "CRL"},
		"product mismatch": {roots: amd.Roots{amd.Genoa: c.ARK}, product: amd.Genoa, want: "not Genoa"},
	} {
		t.Run(name, func(t *testing.T) {
			col := good
			if tc.edit != nil {
				tc.edit(&col)
			}
			roots, product := tc.roots, tc.product
			if roots == nil {
				roots = c.Roots()
			}
			if product == "" {
				product = amd.Turin
			}
			if _, err := amd.Check(roots, product, col, now); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}
