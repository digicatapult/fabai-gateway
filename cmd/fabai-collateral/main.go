// Command fabai-collateral serves AMD attestation collateral to cvmimage
// replicas offline, and fills its cache beforehand.
//
//	fabai-collateral serve -cache DIR [-listen 100.64.0.1:8085]
//	fabai-collateral prep -cache DIR -from-attestation <url|file> [-product P] [-kds URL]
//	fabai-collateral prep -cache DIR -product P -chip-id HEX -tcb 0xHEX [-kds URL]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/amd"
	"github.com/digicatapult/fabai-gateway/internal/collateral"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 10 * time.Second
	usage             = "usage: fabai-collateral serve|prep [flags]; -h after either for its flags"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], log, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, log *slog.Logger, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "serve":
		err = serve(ctx, args[1:], log, stderr)
	case "prep":
		err = prep(ctx, args[1:], log, stderr)
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var usageErr usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &usageErr):
		if usageErr.error != nil {
			fmt.Fprintln(stderr, usageErr)
		}
		return 2
	default:
		log.Error(args[0]+" failed", "error", err.Error())
		return 1
	}
}

// usageError is a mistake in the arguments. A nil error means the flag
// package has already printed it.
type usageError struct{ error }

func parseFlags(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return err
	}
	return usageError{}
}

func serve(ctx context.Context, args []string, log *slog.Logger, stderr io.Writer) error {
	fs := flag.NewFlagSet("fabai-collateral serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", collateral.DefaultListen, "address to listen on, the host end of the replicas' host-only bridge")
	dir := fs.String("cache", "", "collateral cache directory (required)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() > 0 {
		return usageError{errors.New("serve needs -cache, and takes no arguments")}
	}
	cache, err := collateral.LoadCache(*dir, amd.PinnedRoots(), time.Now())
	if err != nil {
		return err
	}
	service, err := collateral.NewService(cache, time.Now, log)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: service, ReadHeaderTimeout: readHeaderTimeout, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(l) }()
	log.Info("collateral service started", "listen", l.Addr().String(), "product", cache.Manifest.Product,
		"chip_id", cache.Manifest.ChipID, "reported_tcb", cache.Manifest.ReportedTCB, "crl_next_update", cache.Manifest.CRLNextUpdate.Format(time.RFC3339))
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errs:
		return err
	}
}

func prep(ctx context.Context, args []string, log *slog.Logger, stderr io.Writer) error {
	fs := flag.NewFlagSet("fabai-collateral prep", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("cache", "", "collateral cache directory to write (required)")
	from := fs.String("from-attestation", "", "a replica's attestation document: a file, or the replica's https://<address>/.well-known/tinfoil-attestation URL")
	product := fs.String("product", "", "Milan, Genoa or Turin; read from the report when it names one")
	chipID := fs.String("chip-id", "", "CHIP_ID, 128 hex digits, without -from-attestation")
	tcb := fs.String("tcb", "", "REPORTED_TCB as 0x followed by 16 hex digits, without -from-attestation")
	kds := fs.String("kds", collateral.DefaultKDS, "AMD Key Distribution Service base URL")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() > 0 {
		return usageError{errors.New("prep needs -cache, and takes no arguments")}
	}
	if *product != "" && !amd.IsProduct(*product) {
		return usageError{fmt.Errorf("unknown product %q", *product)}
	}
	target, err := prepTarget(ctx, *from, *product, *chipID, *tcb)
	if err != nil {
		return err
	}
	m, err := collateral.Prep(ctx, http.DefaultClient, *kds, *dir, target, amd.PinnedRoots(), time.Now())
	if err != nil {
		return err
	}
	log.Info("collateral cache written", "cache", *dir, "product", m.Product, "chip_id", m.ChipID,
		"reported_tcb", m.ReportedTCB, "crl_next_update", m.CRLNextUpdate.Format(time.RFC3339), "report_verified", target.Report != nil)
	return nil
}

func prepTarget(ctx context.Context, from, product, chipID, tcb string) (collateral.Target, error) {
	if from != "" {
		if chipID != "" || tcb != "" {
			return collateral.Target{}, usageError{errors.New("-from-attestation takes the chip ID and TCB from the report: drop -chip-id and -tcb")}
		}
		report, err := collateral.LoadReport(ctx, from)
		if err != nil {
			return collateral.Target{}, err
		}
		return collateral.TargetFromReport(report, product)
	}
	if product == "" || chipID == "" || tcb == "" {
		return collateral.Target{}, usageError{errors.New("prep needs -from-attestation, or all of -product, -chip-id and -tcb")}
	}
	id, err := collateral.ParseChipID(chipID)
	if err != nil {
		return collateral.Target{}, usageError{err}
	}
	raw, err := collateral.ParseTCB(tcb)
	if err != nil {
		return collateral.Target{}, usageError{err}
	}
	return collateral.Target{Product: product, ChipID: id, ReportedTCB: raw}, nil
}
