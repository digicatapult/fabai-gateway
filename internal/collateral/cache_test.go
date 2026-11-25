package collateral_test

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
	"github.com/digicatapult/fabai-gateway/internal/amdtest"
	"github.com/digicatapult/fabai-gateway/internal/collateral"
)

func prepFor(t *testing.T, c *amdtest.Chain, k *kds, target collateral.Target) (string, collateral.Manifest, error) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cache")
	m, err := collateral.Prep(context.Background(), http.DefaultClient, k.server.URL, dir, target, c.Roots(), time.Now())
	return dir, m, err
}

func TestPrep(t *testing.T) {
	c := newChain(t, 0x10)
	next := time.Now().Add(5 * 24 * time.Hour).Truncate(time.Second)
	k := newKDS(t, c, next)
	dir, m, err := prepFor(t, c, k, collateral.Target{Product: amd.Turin, ChipID: c.ChipID, ReportedTCB: turinTCB.Uint64()})
	if err != nil {
		t.Fatal(err)
	}
	if m.Product != amd.Turin || m.ChipID != hex.EncodeToString(c.ChipID[:]) || m.ReportedTCB != collateral.FormatTCB(turinTCB.Uint64()) || !m.CRLNextUpdate.Equal(next) {
		t.Errorf("manifest %+v", m)
	}
	want := []string{
		"/vcek/v1/Turin/" + hex.EncodeToString(c.ChipID[:8]) + "?blSPL=4&fmcSPL=1&snpSPL=25&teeSPL=0&ucodeSPL=74",
		"/vcek/v1/Turin/cert_chain",
		"/vcek/v1/Turin/crl",
	}
	if got := k.requested(); !slices.Equal(got, want) {
		t.Errorf("KDS requests %q, want %q", got, want)
	}
	cache, err := collateral.LoadCache(dir, c.Roots(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if cache.ChipID != c.ChipID || cache.TCB != turinTCB {
		t.Errorf("cache %+v", cache)
	}
}

func TestPrepFromReport(t *testing.T) {
	c := newChain(t, 0x10)
	k := newKDS(t, c, time.Now().Add(time.Hour))
	for name, doc := range map[string][]byte{"v2": v2Document(c.Report(turinTCB.Uint64())), "v3": v3Document(c.Report(turinTCB.Uint64()))} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "attestation.json")
			if err := os.WriteFile(path, doc, 0o600); err != nil {
				t.Fatal(err)
			}
			report, err := collateral.LoadReport(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			target, err := collateral.TargetFromReport(report, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := prepFor(t, c, k, target); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestPrepRefusesReportNotSignedByVCEK(t *testing.T) {
	c := newChain(t, 0x10)
	k := newKDS(t, c, time.Now().Add(time.Hour))
	raw := c.Report(turinTCB.Uint64())
	raw[0x90] ^= 1
	report, err := amd.ParseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	target, err := collateral.TargetFromReport(report, "")
	if err != nil {
		t.Fatal(err)
	}
	dir, _, err := prepFor(t, c, k, target)
	contains(t, err, "doesn't verify the report's signature")
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Error("prep wrote a cache")
	}
}

func TestPrepRefuses(t *testing.T) {
	c := newChain(t, 0x10)
	other := newChain(t, 0x40)
	target := collateral.Target{Product: amd.Turin, ChipID: c.ChipID, ReportedTCB: turinTCB.Uint64()}

	k := newKDS(t, c, time.Now().Add(time.Hour))
	k.vcek = other.VCEK.Raw
	_, _, err := prepFor(t, c, k, target)
	contains(t, err, "KDS returned a VCEK for chip")

	k = newKDS(t, c, time.Now().Add(time.Hour))
	k.status = http.StatusTooManyRequests
	_, _, err = prepFor(t, c, k, target)
	contains(t, err, "retry after 30")

	k = newKDS(t, c, time.Now().Add(-time.Minute))
	_, _, err = prepFor(t, c, k, target)
	contains(t, err, "isn't current")

	_, _, err = prepFor(t, c, newKDS(t, c, time.Now().Add(time.Hour)), collateral.Target{Product: "Naples", ChipID: c.ChipID})
	contains(t, err, "unknown product")
}

func TestTargetFromReport(t *testing.T) {
	c := newChain(t, 0x10)
	report, err := amd.ParseReport(c.Report(turinTCB.Uint64()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collateral.TargetFromReport(report, amd.Genoa); err == nil {
		t.Error("accepted a product the report contradicts")
	}
	raw := c.Report(turinTCB.Uint64())
	raw[0] = 2
	v2, err := amd.ParseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collateral.TargetFromReport(v2, ""); err == nil {
		t.Error("accepted a version 2 report without a product")
	}
	if got, err := collateral.TargetFromReport(v2, amd.Turin); err != nil || got.Product != amd.Turin {
		t.Errorf("version 2 with a product: %+v, %v", got, err)
	}
}

func TestLoadCacheRefuses(t *testing.T) {
	c := newChain(t, 0x10)
	other := newChain(t, 0x40)
	now := time.Now()
	col, err := c.Collateral(now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(col.CRLDER)
	if err != nil {
		t.Fatal(err)
	}
	nextUpdate := parsed.NextUpdate

	_, err = collateral.LoadCache(t.TempDir(), c.Roots(), now)
	contains(t, err, "run fabai-collateral prep")

	dir := t.TempDir()
	if _, err := collateral.WriteCache(dir, amd.Turin, other.ChipID, turinTCB.Uint64(), nextUpdate, col); err != nil {
		t.Fatal(err)
	}
	_, err = collateral.LoadCache(dir, c.Roots(), now)
	contains(t, err, "the cached VCEK is for chip "+hex.EncodeToString(c.ChipID[:8])+", but the configured chip ID is "+hex.EncodeToString(other.ChipID[:8]))

	dir = t.TempDir()
	lower := turinTCB
	lower.SNP--
	if _, err := collateral.WriteCache(dir, amd.Turin, c.ChipID, lower.Uint64(), nextUpdate, col); err != nil {
		t.Fatal(err)
	}
	_, err = collateral.LoadCache(dir, c.Roots(), now)
	contains(t, err, "the cached VCEK is for TCB")

	dir = t.TempDir()
	if _, err := collateral.WriteCache(dir, amd.Turin, c.ChipID, turinTCB.Uint64(), nextUpdate, col); err != nil {
		t.Fatal(err)
	}
	if _, err := collateral.LoadCache(dir, c.Roots(), now); err != nil {
		t.Fatalf("the unedited cache: %v", err)
	}
	_, err = collateral.LoadCache(dir, c.Roots(), nextUpdate)
	contains(t, err, "isn't current")
	_, err = collateral.LoadCache(dir, amd.PinnedRoots(), now)
	contains(t, err, "isn't the pinned")

	if err := os.WriteFile(filepath.Join(dir, collateral.CRLFile), []byte("swapped"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = collateral.LoadCache(dir, c.Roots(), now)
	contains(t, err, "doesn't match its SHA-256")

	manifest, _ := os.ReadFile(filepath.Join(dir, collateral.ManifestFile))
	edited := strings.Replace(string(manifest), `"version":1`, `"version":1,"extra":true`, 1)
	if err := os.WriteFile(filepath.Join(dir, collateral.ManifestFile), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = collateral.LoadCache(dir, c.Roots(), now)
	contains(t, err, "extra")
}
