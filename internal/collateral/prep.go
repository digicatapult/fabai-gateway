package collateral

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
)

const (
	// DefaultKDS is AMD's Key Distribution Service.
	DefaultKDS = "https://kdsintf.amd.com"

	maxFetchSize = 1 << 20
	fetchTimeout = 30 * time.Second
)

// Target is the chip and TCB to fetch a VCEK for.
type Target struct {
	Product     string
	ChipID      [64]byte
	ReportedTCB uint64
	// Report, if set, is the replica report the target came from. Prep then
	// checks that the fetched VCEK signed it.
	Report *amd.Report
}

// TargetFromReport takes the product, chip ID and TCB from a replica's
// report. product is used only if the report doesn't name one (version 2).
func TargetFromReport(r *amd.Report, product string) (Target, error) {
	if r.Product != "" {
		if product != "" && product != r.Product {
			return Target{}, fmt.Errorf("the report is from a %s, not a %s", r.Product, product)
		}
		product = r.Product
	}
	if product == "" {
		return Target{}, errors.New("the report doesn't name its product: give it with -product")
	}
	return Target{Product: product, ChipID: r.ChipID, ReportedTCB: r.ReportedTCB, Report: r}, nil
}

// Prep fetches the VCEK, cert chain and CRL for t from the KDS at kds,
// validates them as the service does at start, and writes them to dir. It
// writes nothing if any check fails.
func Prep(ctx context.Context, client *http.Client, kds, dir string, t Target, roots amd.Roots, now time.Time) (Manifest, error) {
	tcb, err := amd.DecomposeTCB(t.Product, t.ReportedTCB)
	if err != nil {
		return Manifest{}, err
	}
	hwid := amd.HardwareID(t.Product, t.ChipID)
	var col amd.Collateral
	for _, f := range []struct {
		url string
		out *[]byte
	}{
		{amd.VCEKURL(kds, t.Product, hwid, tcb), &col.VCEKDER},
		{amd.CertChainURL(kds, t.Product), &col.CertChainPEM},
		{amd.CRLURL(kds, t.Product), &col.CRLDER},
	} {
		if *f.out, err = fetch(ctx, client, f.url); err != nil {
			return Manifest{}, err
		}
	}
	checked, err := amd.Check(roots, t.Product, col, now)
	if err != nil {
		return Manifest{}, fmt.Errorf("the fetched collateral: %w", err)
	}
	if !bytes.Equal(checked.HardwareID, hwid) || checked.TCB != tcb {
		return Manifest{}, fmt.Errorf("KDS returned a VCEK for chip %x at TCB %s, not chip %x at TCB %s", checked.HardwareID, checked.TCB, hwid, tcb)
	}
	if t.Report != nil {
		if err := t.Report.VerifySignature(checked.VCEK.PublicKey.(*ecdsa.PublicKey)); err != nil {
			return Manifest{}, fmt.Errorf("the replica's report: %w", err)
		}
	}
	m, err := WriteCache(dir, t.Product, t.ChipID, t.ReportedTCB, checked.NextUpdate, col)
	if err != nil {
		return Manifest{}, fmt.Errorf("writing the cache: %w", err)
	}
	if _, err := LoadCache(dir, roots, now); err != nil {
		return Manifest{}, fmt.Errorf("the written cache doesn't load: %w", err)
	}
	return m, nil
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchSize+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if len(body) > maxFetchSize {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", url, maxFetchSize)
	}
	if resp.StatusCode != http.StatusOK {
		hint := ""
		if retry := resp.Header.Get("Retry-After"); retry != "" {
			hint = ", retry after " + retry
		}
		return nil, fmt.Errorf("GET %s: %s%s", url, resp.Status, hint)
	}
	return body, nil
}

// LoadReport reads a replica's attestation document from a file, or fetches
// it from an http(s) URL, and returns its report. A replica's TLS
// certificate isn't checked: it is self-signed, and Prep authenticates the
// report itself against AMD's chain.
func LoadReport(ctx context.Context, source string) (*amd.Report, error) {
	var doc []byte
	var err error
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
		doc, err = fetch(ctx, client, source)
	} else {
		doc, err = os.ReadFile(source)
	}
	if err != nil {
		return nil, err
	}
	return ReportFromDocument(doc)
}
