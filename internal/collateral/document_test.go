package collateral_test

import (
	"bytes"
	"testing"

	"github.com/digicatapult/fabai-gateway/internal/collateral"
)

func TestReportFromDocument(t *testing.T) {
	c := newChain(t, 0x10)
	raw := c.Report(turinTCB.Uint64())
	for name, doc := range map[string][]byte{"v2": v2Document(raw), "v3": v3Document(raw)} {
		report, err := collateral.ReportFromDocument(doc)
		if err != nil || report.ChipID != c.ChipID || report.ReportedTCB != turinTCB.Uint64() {
			t.Errorf("%s: %+v, %v", name, report, err)
		}
	}
	for name, doc := range map[string][]byte{
		"not JSON":       []byte("nope"),
		"unknown format": []byte(`{"format":"https://tinfoil.sh/predicate/tdx-guest/v2","body":""}`),
		"v3 without CPU": []byte(`{"format":"https://tinfoil.sh/predicate/attestation/v3"}`),
		"v3 bad base64":  []byte(`{"format":"https://tinfoil.sh/predicate/attestation/v3","cpu_evidence":{"format":"https://tinfoil.sh/format/sev-snp-report/v1","report_base64":"!"}}`),
		"v2 not gzip":    []byte(`{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v2","body":"AAAA"}`),
		"v2 too long":    v2Document(append(bytes.Clone(raw), 0)),
	} {
		if _, err := collateral.ReportFromDocument(doc); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
