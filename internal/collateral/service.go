package collateral

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
)

const (
	// Path is the endpoint cvmimage's collateral client posts to.
	Path = "/attestation-collaterals"
	// DefaultListen is the host end of the demo's host-only bridge. Every
	// deployment config's measured shim.atc names it.
	DefaultListen = "100.64.0.1:8085"

	responseFormat  = "https://tinfoil.sh/predicate/attestation-collaterals/v2"
	vcekFormat      = "https://tinfoil.sh/collateral/amd-vcek/v1"
	crlFormat       = "https://tinfoil.sh/collateral/amd-crl/v1"
	roleEndorsement = "endorsement"
	subjectCPU      = "cpu"
	maxRequestBody  = 1 << 20
)

type entry struct {
	ID       string   `json:"id"`
	Role     string   `json:"role"`
	Format   string   `json:"format"`
	Subjects []string `json:"subjects"`
	Data     any      `json:"data"`
}

type response struct {
	Format     string    `json:"format"`
	ExpiresAt  time.Time `json:"expires_at"`
	Collateral []entry   `json:"collateral"`
}

// Service answers cvmimage's collateral requests from a validated cache.
// Every well-formed request gets the same response; the request is read only
// to warn when the replica's chip or TCB differs from the cache's.
type Service struct {
	cache     *Cache
	response  []byte
	expiresAt time.Time
	now       func() time.Time
	log       *slog.Logger
}

// NewService returns a Service for cache. now is the clock it checks the
// CRL's expiry against.
func NewService(cache *Cache, now func() time.Time, log *slog.Logger) (*Service, error) {
	col := cache.Collateral
	body, err := json.Marshal(response{
		Format:    responseFormat,
		ExpiresAt: cache.Manifest.CRLNextUpdate.UTC(),
		Collateral: []entry{
			{ID: "amd-vcek", Role: roleEndorsement, Format: vcekFormat, Subjects: []string{subjectCPU}, Data: struct {
				VCEK  string `json:"vcek_der_base64"`
				Chain string `json:"cert_chain_pem"`
			}{base64.StdEncoding.EncodeToString(col.VCEKDER), string(col.CertChainPEM)}},
			{ID: "amd-crl", Role: roleEndorsement, Format: crlFormat, Subjects: []string{subjectCPU}, Data: struct {
				CRL string `json:"crl_der_base64"`
			}{base64.StdEncoding.EncodeToString(col.CRLDER)}},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Service{cache: cache, response: body, expiresAt: cache.Manifest.CRLNextUpdate, now: now, log: log}, nil
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status := s.serve(w, r)
	s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", status)
}

func (s *Service) serve(w http.ResponseWriter, r *http.Request) int {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return http.StatusNotFound
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		if errors.As(err, new(*http.MaxBytesError)) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return http.StatusRequestEntityTooLarge
		}
		http.Error(w, "reading request body", http.StatusBadRequest)
		return http.StatusBadRequest
	}
	var req struct {
		Document jsontext.Value `json:"document"`
	}
	if err := json.Unmarshal(body, &req); err != nil || !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		http.Error(w, "the request isn't a JSON object", http.StatusBadRequest)
		return http.StatusBadRequest
	}
	s.warnOnMismatch(req.Document)
	if !s.now().Before(s.expiresAt) {
		s.log.Error("the cached CRL has expired: run fabai-collateral prep to refresh the cache", "crl_next_update", s.expiresAt.Format(time.RFC3339))
		http.Error(w, "collateral expired", http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.response)
	return http.StatusOK
}

// warnOnMismatch logs when the request's report names another chip or TCB
// than the cache. The report isn't authenticated; this is for the operator.
func (s *Service) warnOnMismatch(doc jsontext.Value) {
	if len(doc) == 0 {
		s.log.Warn("the request carries no attestation document")
		return
	}
	report, err := ReportFromDocument(doc)
	if err != nil {
		s.log.Warn("the request's report can't be read", "error", err.Error())
		return
	}
	product := s.cache.Manifest.Product
	got, want := amd.HardwareID(product, report.ChipID), amd.HardwareID(product, s.cache.ChipID)
	if !bytes.Equal(got, want) {
		s.log.Warn("the replica's chip isn't the cached VCEK's", "request_chip_id", hex.EncodeToString(got), "cached_chip_id", hex.EncodeToString(want))
	}
	tcb, err := amd.DecomposeTCB(product, report.ReportedTCB)
	if err != nil || tcb != s.cache.TCB {
		s.log.Warn("the replica's REPORTED_TCB isn't the cached VCEK's: run fabai-collateral prep for the new TCB",
			"request_reported_tcb", FormatTCB(report.ReportedTCB), "cached_reported_tcb", s.cache.Manifest.ReportedTCB)
	}
}
