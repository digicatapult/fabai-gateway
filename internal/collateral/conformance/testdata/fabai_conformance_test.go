package attestationmaterial

// Added to a scratch checkout of cvmimage by fabai-gateway's
// scripts/check-cvmimage-client.sh: cvmimage's own collateral client, and
// its cache, run against fabai-collateral at FABAI_COLLATERAL_URL.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func TestFabAICollateralService(t *testing.T) {
	base := os.Getenv("FABAI_COLLATERAL_URL")
	if base == "" {
		t.Skip("FABAI_COLLATERAL_URL isn't set")
	}
	client, err := NewClient(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		Version:  RequestVersionDocument,
		Repo:     "digicatapult/fabai-demo",
		Tag:      "v1.0.0",
		Document: json.RawMessage(`{"format":"https://tinfoil.sh/predicate/attestation/v3"}`),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := client.Fetch(ctx, request)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	set, err := collateral.Decode(response.Collateral)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if set.CPU.AMDVCEK == nil || set.CPU.AMDCRL == nil {
		t.Fatalf("the response doesn't carry the CPU's VCEK and CRL: %+v", set.CPU)
	}

	entries, err := NewCache(request, client).Current(ctx)
	if err != nil {
		t.Fatalf("Cache.Current: %v", err)
	}
	if len(entries) != len(response.Collateral) {
		t.Fatalf("the cache serves %d entries, want %d", len(entries), len(response.Collateral))
	}
}
