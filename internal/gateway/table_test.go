package gateway

import (
	"encoding/json/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validTable = `{
	"models": {
		"fabai-chat": {"repo": "digicatapult/fabai-demo", "hosts": ["protected.fabai.internal"]}
	},
	"hosts": {
		"protected.fabai.internal": {"upstream": "100.64.0.2:443"}
	}
}`

func TestParseTable(t *testing.T) {
	table, err := ParseTable([]byte(validTable))
	if err != nil {
		t.Fatal(err)
	}
	if got := table.Hosts[protectedHost].Upstream; got != netip.MustParseAddrPort("100.64.0.2:443") {
		t.Errorf("upstream %v", got)
	}
}

func TestLoadTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte(validTable), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTable(path); err != nil {
		t.Error(err)
	}
	if _, err := LoadTable(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("loaded a missing file")
	}
}

func TestParseTableRefuses(t *testing.T) {
	for name, tc := range map[string]struct{ from, to string }{
		"unknown member":       {`"hosts": {`, `"extra": 1, "hosts": {`},
		"repeated member":      {`"hosts": {`, `"models": {}, "hosts": {`},
		"no models":            {`"fabai-chat": {"repo": "digicatapult/fabai-demo", "hosts": ["protected.fabai.internal"]}`, ``},
		"empty repo":           {`"repo": "digicatapult/fabai-demo"`, `"repo": " "`},
		"no hosts for a model": {`"hosts": ["protected.fabai.internal"]`, `"hosts": []`},
		"undeclared host":      {`"hosts": ["protected.fabai.internal"]`, `"hosts": ["protected.fabai.internal", "other.fabai.internal"]`},
		"host named twice":     {`"hosts": ["protected.fabai.internal"]`, `"hosts": ["protected.fabai.internal", "protected.fabai.internal"]`},
		"unused host":          {`"protected.fabai.internal": {"upstream": "100.64.0.2:443"}`, `"protected.fabai.internal": {"upstream": "100.64.0.2:443"}, "spare.fabai.internal": {"upstream": "100.64.0.3:443"}`},
		"uppercase host":       {`protected.fabai.internal`, `Protected.fabai.internal`},
		"host with a port":     {`protected.fabai.internal`, `protected.fabai.internal:443`},
		"upstream hostname":    {`"100.64.0.2:443"`, `"replica.local:443"`},
		"upstream no port":     {`"100.64.0.2:443"`, `"100.64.0.2"`},
		"upstream port zero":   {`"100.64.0.2:443"`, `"100.64.0.2:0"`},
		"upstream missing":     {`{"upstream": "100.64.0.2:443"}`, `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			data := strings.ReplaceAll(validTable, tc.from, tc.to)
			if data == validTable {
				t.Fatal("the edit changed nothing")
			}
			if _, err := ParseTable([]byte(data)); err == nil {
				t.Errorf("accepted:\n%s", data)
			}
		})
	}
}

func TestCatalog(t *testing.T) {
	table, err := ParseTable([]byte(validTable))
	if err != nil {
		t.Fatal(err)
	}
	data, err := table.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]struct {
		Repo  string   `json:"repo"`
		Hosts []string `json:"hosts"`
	}
	if err := json.Unmarshal(data, &got, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("%s: %v", data, err)
	}
	entry := got[testModel]
	if len(got) != 1 || entry.Repo != "digicatapult/fabai-demo" || len(entry.Hosts) != 1 || entry.Hosts[0] != protectedHost {
		t.Errorf("catalog %s", data)
	}
}
