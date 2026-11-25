// Command conformance serves fabai-collateral's handler over a synthetic
// cache, for scripts/check-cvmimage-client.sh. It writes its address to
// -addr-file once it is listening, and serves until it is stopped.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
	"github.com/digicatapult/fabai-gateway/internal/amdtest"
	"github.com/digicatapult/fabai-gateway/internal/collateral"
)

func main() {
	addrFile := flag.String("addr-file", "", "file to write the listening address to (required)")
	flag.Parse()
	if *addrFile == "" {
		fmt.Fprintln(os.Stderr, "usage: conformance -addr-file FILE")
		os.Exit(2)
	}
	if err := run(*addrFile); err != nil {
		fmt.Fprintln(os.Stderr, "conformance:", err)
		os.Exit(1)
	}
}

func run(addrFile string) error {
	chain, err := amdtest.New(amdtest.ChipID(1), amd.TCB{Product: amd.Turin, FMC: 1, Bootloader: 4, SNP: 25, Microcode: 74})
	if err != nil {
		return err
	}
	next := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	col, err := chain.Collateral(next)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "fabai-collateral-conformance-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if _, err := collateral.WriteCache(dir, chain.Product, chain.ChipID, chain.TCB.Uint64(), next, col); err != nil {
		return err
	}
	cache, err := collateral.LoadCache(dir, chain.Roots(), time.Now())
	if err != nil {
		return err
	}
	service, err := collateral.NewService(cache, time.Now, slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	tmp := addrFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(l.Addr().String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Clean(addrFile)); err != nil {
		return err
	}
	server := &http.Server{Handler: service, ReadHeaderTimeout: 10 * time.Second}
	if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
