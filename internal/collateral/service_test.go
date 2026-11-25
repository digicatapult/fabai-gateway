package collateral_test

import (
	"encoding/base64"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
	"github.com/digicatapult/fabai-gateway/internal/amdtest"
	"github.com/digicatapult/fabai-gateway/internal/collateral"
)

type wireResponse struct {
	Format     string    `json:"format"`
	ExpiresAt  time.Time `json:"expires_at"`
	Collateral []struct {
		ID       string            `json:"id"`
		Role     string            `json:"role"`
		Format   string            `json:"format"`
		Subjects []string          `json:"subjects"`
		Data     map[string]string `json:"data"`
	} `json:"collateral"`
}

type fixture struct {
	chain      *amdtest.Chain
	col        amd.Collateral
	nextUpdate time.Time
	service    *collateral.Service
	logs       *logBuffer
	clock      time.Time
}

func newService(t *testing.T) *fixture {
	t.Helper()
	c := newChain(t, 0x10)
	f := &fixture{chain: c, nextUpdate: time.Now().Add(48 * time.Hour).Truncate(time.Second), clock: time.Now()}
	k := newKDS(t, c, f.nextUpdate)
	dir, _, err := prepFor(t, c, k, collateral.Target{Product: amd.Turin, ChipID: c.ChipID, ReportedTCB: turinTCB.Uint64()})
	if err != nil {
		t.Fatal(err)
	}
	cache, err := collateral.LoadCache(dir, c.Roots(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.col = cache.Collateral
	var log *slog.Logger
	log, f.logs = newLogger()
	if f.service, err = collateral.NewService(cache, func() time.Time { return f.clock }, log); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	f.service.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestCollateralResponse(t *testing.T) {
	f := newService(t)
	rec := f.do(t, http.MethodPost, collateral.Path, collateralRequest("digicatapult/fabai-demo", v3Document(f.chain.Report(turinTCB.Uint64()))))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v: %s", rec.Code, rec.Header(), rec.Body)
	}
	var resp wireResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if resp.Format != "https://tinfoil.sh/predicate/attestation-collaterals/v2" || !resp.ExpiresAt.Equal(f.nextUpdate) || len(resp.Collateral) != 2 {
		t.Fatalf("%+v", resp)
	}
	vcek, crl := resp.Collateral[0], resp.Collateral[1]
	if vcek.ID != "amd-vcek" || vcek.Format != "https://tinfoil.sh/collateral/amd-vcek/v1" || crl.ID != "amd-crl" || crl.Format != "https://tinfoil.sh/collateral/amd-crl/v1" {
		t.Errorf("entries %+v", resp.Collateral)
	}
	for _, e := range resp.Collateral {
		if e.Role != "endorsement" || len(e.Subjects) != 1 || e.Subjects[0] != "cpu" {
			t.Errorf("%s: role %q, subjects %q", e.ID, e.Role, e.Subjects)
		}
	}
	if vcek.Data["vcek_der_base64"] != base64.StdEncoding.EncodeToString(f.col.VCEKDER) || vcek.Data["cert_chain_pem"] != string(f.col.CertChainPEM) || len(vcek.Data) != 2 {
		t.Error("amd-vcek data")
	}
	if crl.Data["crl_der_base64"] != base64.StdEncoding.EncodeToString(f.col.CRLDER) || len(crl.Data) != 1 {
		t.Error("amd-crl data")
	}
	if strings.Contains(f.logs.String(), "WARN") {
		t.Errorf("a matching report was warned about:\n%s", f.logs)
	}
}

func TestAnyRepository(t *testing.T) {
	f := newService(t)
	doc := v3Document(f.chain.Report(turinTCB.Uint64()))
	a := f.do(t, http.MethodPost, collateral.Path, collateralRequest("digicatapult/fabai-demo", doc))
	b := f.do(t, http.MethodPost, collateral.Path, collateralRequest("someone/else", doc))
	if a.Code != http.StatusOK || a.Body.String() != b.Body.String() {
		t.Error("two repositories got different responses")
	}
}

func TestCollateralRefuses(t *testing.T) {
	f := newService(t)
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodPost, "/other", "{}", http.StatusNotFound},
		{http.MethodPost, collateral.Path + "/", "{}", http.StatusNotFound},
		{http.MethodGet, collateral.Path, "", http.StatusMethodNotAllowed},
		{http.MethodPost, collateral.Path, strings.Repeat(" ", 1<<20+1), http.StatusRequestEntityTooLarge},
		{http.MethodPost, collateral.Path, "not JSON", http.StatusBadRequest},
		{http.MethodPost, collateral.Path, "null", http.StatusBadRequest},
		{http.MethodPost, collateral.Path, "[]", http.StatusBadRequest},
	} {
		if rec := f.do(t, tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

func TestExpiredCRL(t *testing.T) {
	f := newService(t)
	f.clock = f.nextUpdate
	rec := f.do(t, http.MethodPost, collateral.Path, collateralRequest("r", v3Document(f.chain.Report(turinTCB.Uint64()))))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("%d", rec.Code)
	}
	if !strings.Contains(f.logs.String(), "run fabai-collateral prep") {
		t.Errorf("logs:\n%s", f.logs)
	}
}

func TestMismatchWarning(t *testing.T) {
	f := newService(t)
	other := newChain(t, 0x40)
	higher := turinTCB
	higher.SNP++
	for name, tc := range map[string]struct {
		doc  []byte
		want []string
	}{
		"stale TCB":   {v3Document(f.chain.Report(higher.Uint64())), []string{collateral.FormatTCB(higher.Uint64()), collateral.FormatTCB(turinTCB.Uint64())}},
		"other chip":  {v3Document(other.Report(turinTCB.Uint64())), []string{"4041424344454647", "1011121314151617"}},
		"v2 document": {v2Document(other.Report(turinTCB.Uint64())), []string{"chip isn't"}},
		"no report":   {[]byte(`{"format":"https://tinfoil.sh/predicate/attestation/v3"}`), []string{"can't be read"}},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(f.logs.String())
			if rec := f.do(t, http.MethodPost, collateral.Path, collateralRequest("r", tc.doc)); rec.Code != http.StatusOK {
				t.Fatalf("%d: the cached collateral wasn't served", rec.Code)
			}
			logs := f.logs.String()[before:]
			for _, want := range tc.want {
				if !strings.Contains(logs, want) {
					t.Errorf("logs don't contain %q:\n%s", want, logs)
				}
			}
		})
	}
	if rec := f.do(t, http.MethodPost, collateral.Path, `{"version":2,"repo":"r"}`); rec.Code != http.StatusOK || !strings.Contains(f.logs.String(), "no attestation document") {
		t.Errorf("no document: %d", rec.Code)
	}
}
