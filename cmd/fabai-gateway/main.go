// Command fabai-gateway runs the untrusted gateway between gateway clients
// and cvmimage inference replicas.
//
//	fabai-gateway -routes routes.json -cert gateway.crt -key gateway.key \
//	  [-listen :443] [-admin-socket /run/fabai-gateway/admin.sock] [-origin https://kiosk ...]
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/digicatapult/fabai-gateway/internal/gateway"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 2 * time.Minute
	shutdownTimeout   = 30 * time.Second
)

type origins []string

func (o *origins) String() string     { return fmt.Sprint([]string(*o)) }
func (o *origins) Set(v string) error { *o = append(*o, v); return nil }

type config struct {
	listen, routes, cert, key, adminSocket string
	origins                                origins
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := parseFlags(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		log.Error("invalid arguments", "error", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil {
		log.Error("gateway stopped", "error", err.Error())
		os.Exit(1)
	}
}

func parseFlags(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("fabai-gateway", flag.ContinueOnError)
	fs.StringVar(&cfg.listen, "listen", ":443", "client listener address")
	fs.StringVar(&cfg.routes, "routes", "", "routing table (JSON)")
	fs.StringVar(&cfg.cert, "cert", "", "client listener certificate chain (PEM)")
	fs.StringVar(&cfg.key, "key", "", "client listener private key (PEM)")
	fs.StringVar(&cfg.adminSocket, "admin-socket", "/run/fabai-gateway/admin.sock", "admin interface Unix socket")
	fs.Var(&cfg.origins, "origin", "browser origin allowed by CORS (repeatable)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if cfg.routes == "" || cfg.cert == "" || cfg.key == "" {
		return config{}, errors.New("-routes, -cert and -key are required")
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return cfg, nil
}

func run(ctx context.Context, cfg config, log *slog.Logger) error {
	table, err := gateway.LoadTable(cfg.routes)
	if err != nil {
		return err
	}
	routes, err := gateway.NewRoutes(table, log)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.cert, cfg.key)
	if err != nil {
		return fmt.Errorf("loading the client certificate: %w", err)
	}
	inner, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("client listener: %w", err)
	}
	adminListener, err := gateway.ListenAdmin(cfg.adminSocket, log)
	if err != nil {
		_ = inner.Close()
		return err
	}

	errorLog := slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	client := &http.Server{
		Handler:           gateway.New(routes, cfg.origins, log),
		Protocols:         &protocols,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          errorLog,
	}
	admin := &http.Server{Handler: gateway.AdminHandler(routes), ReadHeaderTimeout: readHeaderTimeout, ErrorLog: errorLog}

	errs := make(chan error, 2)
	go func() { errs <- client.Serve(gateway.ListenTLS(inner, gateway.ClientTLSConfig(cert))) }()
	go func() { errs <- admin.Serve(adminListener) }()
	log.Info("gateway started", "listen", inner.Addr().String(), "admin_socket", cfg.adminSocket, "models", len(table.Models), "hosts", len(table.Hosts))

	shutdown := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return errors.Join(client.Shutdown(shutdownCtx), admin.Shutdown(shutdownCtx))
	}
	select {
	case <-ctx.Done():
		log.Info("shutting down")
		return shutdown()
	case err := <-errs:
		return errors.Join(err, shutdown())
	}
}
