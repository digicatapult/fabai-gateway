package collateral_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
	"github.com/digicatapult/fabai-gateway/internal/amdtest"
)

var turinTCB = amd.TCB{Product: amd.Turin, FMC: 1, Bootloader: 4, TEE: 0, SNP: 25, Microcode: 74}

func newChain(t *testing.T, first byte) *amdtest.Chain {
	t.Helper()
	c, err := amdtest.New(amdtest.ChipID(first), turinTCB)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// kds is a stand-in for AMD's Key Distribution Service.
type kds struct {
	server *httptest.Server
	mu     sync.Mutex
	paths  []string
	vcek   []byte
	status int
}

func newKDS(t *testing.T, c *amdtest.Chain, nextUpdate time.Time) *kds {
	t.Helper()
	crl, err := c.CRL(time.Now().Add(-time.Hour), nextUpdate)
	if err != nil {
		t.Fatal(err)
	}
	k := &kds{vcek: c.VCEK.Raw, status: http.StatusOK}
	prefix := "/vcek/v1/" + c.Product + "/"
	k.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		k.paths = append(k.paths, r.URL.RequestURI())
		status, vcek := k.status, k.vcek
		k.mu.Unlock()
		if status != http.StatusOK {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(status)
			return
		}
		switch r.URL.Path {
		case prefix + "cert_chain":
			_, _ = w.Write(c.CertChainPEM())
		case prefix + "crl":
			_, _ = w.Write(crl)
		case prefix + hex.EncodeToString(amd.HardwareID(c.Product, c.ChipID)):
			_, _ = w.Write(vcek)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(k.server.Close)
	return k
}

func (k *kds) requested() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.paths...)
}

func v3Document(report []byte) []byte {
	return fmt.Appendf(nil, `{"format":"https://tinfoil.sh/predicate/attestation/v3","challenge":{},"cpu_evidence":{"format":"https://tinfoil.sh/format/sev-snp-report/v1","report_base64":%q}}`,
		base64.StdEncoding.EncodeToString(report))
}

func v2Document(report []byte) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(report)
	_ = zw.Close()
	return fmt.Appendf(nil, `{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v2","body":%q}`, base64.StdEncoding.EncodeToString(b.Bytes()))
}

// collateralRequest is the request cvmimage's collateral client sends.
func collateralRequest(repo string, doc []byte) string {
	return fmt.Sprintf(`{"version":2,"repo":%q,"tag":"v1.0.0","document":%s}`, repo, doc)
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newLogger() (*slog.Logger, *logBuffer) {
	b := &logBuffer{}
	return slog.New(slog.NewJSONHandler(b, nil)), b
}

func contains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("error %v, want %q", err, want)
	}
}
