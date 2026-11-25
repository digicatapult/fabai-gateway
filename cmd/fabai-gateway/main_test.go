package main

import (
	"slices"
	"testing"
)

func TestParseFlags(t *testing.T) {
	cfg, err := parseFlags([]string{"-routes", "r.json", "-cert", "c.pem", "-key", "k.pem", "-origin", "https://a", "-origin", "https://b"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.listen != ":443" || cfg.adminSocket != "/run/fabai-gateway/admin.sock" || !slices.Equal(cfg.origins, origins{"https://a", "https://b"}) {
		t.Errorf("%+v", cfg)
	}
	for _, args := range [][]string{
		nil,
		{"-routes", "r.json", "-cert", "c.pem"},
		{"-routes", "r.json", "-cert", "c.pem", "-key", "k.pem", "extra"},
		{"-unknown"},
	} {
		if _, err := parseFlags(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
