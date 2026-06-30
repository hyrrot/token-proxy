// Command token-proxy is a development-only credential-injecting forward proxy.
package main

import (
	"context"
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

	"github.com/hyrrot/token-proxy/internal/ca"
	"github.com/hyrrot/token-proxy/internal/config"
	"github.com/hyrrot/token-proxy/internal/proxy"
	"github.com/hyrrot/token-proxy/internal/secrets"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "ca":
		err = runCA(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `token-proxy — development-only credential-injecting forward proxy

Usage:
  token-proxy serve [flags]   Start the proxy
  token-proxy ca   [flags]    Show the internal CA path and trust instructions

Run "token-proxy serve -h" or "token-proxy ca -h" for flags.
`)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "token-proxy.yaml", "path to config file")
	listen := fs.String("listen", "", "override listen address (host:port)")
	caDir := fs.String("ca-dir", "", "override CA directory")
	allowPublic := fs.Bool("allow-public", false, "permit binding to a non-loopback address (UNSAFE: exposes injected credentials to your network)")
	verbose := fs.Bool("verbose", false, "enable debug logging")
	fs.Parse(args)

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *caDir != "" {
		cfg.CA.Dir = *caDir
	}

	if err := guardBind(cfg.Listen, *allowPublic); err != nil {
		return err
	}

	authority, err := ca.LoadOrCreate(cfg.CA.Dir)
	if err != nil {
		return err
	}
	resolver := secrets.NewResolver(cfg.Cache.TTL.Or(5 * time.Minute))
	resolver.Register(secrets.NewOnePassword())
	resolver.Register(secrets.NewGSM())

	handler, err := proxy.New(cfg, authority, resolver, log)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: handler,
		// No global timeouts: a forward proxy holds long-lived CONNECT
		// tunnels. Per-hop timeouts live in the upstream transport.
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	log.Info("token-proxy listening",
		"addr", ln.Addr().String(),
		"ca", authority.CertPath(),
		"rules", len(cfg.Rules))
	if isLoopbackHost(hostOf(cfg.Listen)) {
		log.Info("bound to loopback only (development mode)")
	} else {
		log.Warn("bound to a NON-loopback address; injected credentials are reachable from your network")
	}

	idleClosed := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		close(idleClosed)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-idleClosed
	return nil
}

func runCA(args []string) error {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	caDir := fs.String("ca-dir", "", "override CA directory")
	configPath := fs.String("config", "token-proxy.yaml", "config file to read the CA directory from")
	fs.Parse(args)

	dir := *caDir
	if dir == "" {
		if cfg, err := config.Load(*configPath); err == nil {
			dir = cfg.CA.Dir
		} else {
			dir = config.DefaultCADir()
		}
	}
	authority, err := ca.LoadOrCreate(dir)
	if err != nil {
		return err
	}
	path := authority.CertPath()
	fmt.Printf(`Internal CA certificate: %s

Tell your tools to trust it (development machines only):

  curl / git:   export SSL_CERT_FILE=%s
  Node.js:      export NODE_EXTRA_CA_CERTS=%s
  Python:       export REQUESTS_CA_BUNDLE=%s
                export SSL_CERT_FILE=%s

And route traffic through the proxy:

  export HTTP_PROXY=http://127.0.0.1:8080
  export HTTPS_PROXY=http://127.0.0.1:8080

Do NOT add this CA to your OS/system trust store: anything signed by it would
be trusted everywhere. Prefer the per-tool environment variables above.
`, path, path, path, path, path)
	return nil
}

// guardBind refuses to start on a non-loopback address unless explicitly
// allowed, so credentials are not accidentally exposed to the network.
func guardBind(addr string, allowPublic bool) error {
	host := hostOf(addr)
	if isLoopbackHost(host) || allowPublic {
		return nil
	}
	return fmt.Errorf(
		"refusing to bind %q: it is not a loopback address. token-proxy injects real credentials "+
			"and is development-only. Bind 127.0.0.1 instead, or pass --allow-public if you really "+
			"mean to expose it to your network", addr)
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func isLoopbackHost(host string) bool {
	switch host {
	case "", "localhost":
		// Empty host means "all interfaces" (e.g. ":8080"); treat as public.
		return host == "localhost"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
