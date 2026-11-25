package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
	"github.com/digicatapult/fabai-gateway/internal/amdtest"
)

func runCommand(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, nil))
	code := run(context.Background(), args, log, &out)
	return code, out.String()
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"other"},
		{"serve"},
		{"serve", "-cache", "c", "extra"},
		{"prep", "-cache", "c"},
		{"prep", "-cache", "c", "-product", "Turin", "-chip-id", "00"},
		{"prep", "-cache", "c", "-product", "Naples", "-chip-id", strings.Repeat("0", 128), "-tcb", "0x0"},
		{"prep", "-cache", "c", "-product", "Turin", "-chip-id", strings.Repeat("0", 127), "-tcb", "0x0"},
		{"prep", "-cache", "c", "-product", "Turin", "-chip-id", strings.Repeat("0", 128), "-tcb", "17"},
		{"prep", "-cache", "c", "-from-attestation", "doc.json", "-tcb", "0x0"},
		{"serve", "-unknown"},
	} {
		if code, out := runCommand(t, args...); code != 2 {
			t.Errorf("%v: exit %d\n%s", args, code, out)
		}
	}
	if code, _ := runCommand(t, "serve", "-h"); code != 0 {
		t.Errorf("serve -h: exit %d", code)
	}
}

func TestServeWithoutCache(t *testing.T) {
	code, out := runCommand(t, "serve", "-cache", t.TempDir(), "-listen", "127.0.0.1:0")
	if code != 1 || !strings.Contains(out, "run fabai-collateral prep") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// TestPrepTrustsOnlyAMD runs prep against a synthetic KDS: the command uses
// AMD's pinned roots, so the synthetic chain is refused and nothing written.
func TestPrepTrustsOnlyAMD(t *testing.T) {
	c, err := amdtest.New(amdtest.ChipID(1), amd.TCB{Product: amd.Turin, SNP: 3})
	if err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(doc, []byte(`{"format":"https://tinfoil.sh/predicate/attestation/v3","cpu_evidence":{"format":"https://tinfoil.sh/format/sev-snp-report/v1","report_base64":"`+b64(c.Report(c.TCB.Uint64()))+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	kds := serveKDS(t, c)
	cache := filepath.Join(t.TempDir(), "cache")
	code, out := runCommand(t, "prep", "-cache", cache, "-from-attestation", doc, "-kds", kds)
	if code != 1 || !strings.Contains(out, "isn't the pinned Turin root") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Error("prep wrote a cache")
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// serveKDS serves c's VCEK, cert chain and a current CRL at KDS paths.
func serveKDS(t *testing.T, c *amdtest.Chain) string {
	t.Helper()
	crl, err := c.CRL(time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	prefix := "/vcek/v1/" + c.Product + "/"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case prefix + "cert_chain":
			_, _ = w.Write(c.CertChainPEM())
		case prefix + "crl":
			_, _ = w.Write(crl)
		case prefix + hex.EncodeToString(amd.HardwareID(c.Product, c.ChipID)):
			_, _ = w.Write(c.VCEK.Raw)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}
