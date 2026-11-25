package collateral

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"

	"github.com/digicatapult/fabai-gateway/internal/amd"
)

// Document formats that carry an SEV-SNP report.
const (
	formatV3        = "https://tinfoil.sh/predicate/attestation/v3"
	formatV2SEVSNP  = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	formatSEVReport = "https://tinfoil.sh/format/sev-snp-report/v1"
)

// ReportFromDocument returns the SEV-SNP report in a cvmimage attestation
// document: a v3 document's cpu_evidence, or a v2 document's gzipped body.
// The report isn't authenticated here.
func ReportFromDocument(doc []byte) (*amd.Report, error) {
	var d struct {
		Format      string `json:"format"`
		Body        string `json:"body"`
		CPUEvidence *struct {
			Format       string `json:"format"`
			ReportBase64 string `json:"report_base64"`
		} `json:"cpu_evidence"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, fmt.Errorf("attestation document: %w", err)
	}
	var raw []byte
	var err error
	switch {
	case d.Format == formatV3:
		if d.CPUEvidence == nil || d.CPUEvidence.Format != formatSEVReport {
			return nil, errors.New("the v3 document carries no SEV-SNP report")
		}
		raw, err = base64.StdEncoding.DecodeString(d.CPUEvidence.ReportBase64)
	case d.Format == formatV2SEVSNP:
		raw, err = gunzipBase64(d.Body)
	default:
		return nil, fmt.Errorf("attestation document format %q carries no SEV-SNP report", d.Format)
	}
	if err != nil {
		return nil, fmt.Errorf("attestation document report: %w", err)
	}
	return amd.ParseReport(raw)
}

func gunzipBase64(body string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	// A report is 1184 bytes; read one more to refuse anything longer.
	raw, err := io.ReadAll(io.LimitReader(zr, amd.ReportSize+1))
	if err != nil {
		return nil, err
	}
	return raw, zr.Close()
}
