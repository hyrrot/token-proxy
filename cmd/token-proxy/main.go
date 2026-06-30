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
	"strings"
	"syscall"
	"time"

	"github.com/hyrrot/token-proxy/internal/ca"
	"github.com/hyrrot/token-proxy/internal/config"
	"github.com/hyrrot/token-proxy/internal/proxy"
	"github.com/hyrrot/token-proxy/internal/secrets"
)

// version is the build version, overridden at release time via
// -ldflags "-X main.version=...".
var version = "dev"

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
	case "version", "--version", "-v":
		fmt.Println("token-proxy", version)
		return
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
  token-proxy version         Print the version

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
	watch := fs.Bool("watch", true, "hot-reload the config file when it changes (SIGHUP always reloads)")
	reloadInterval := fs.Duration("reload-interval", time.Second, "how often to check the config file for changes when --watch is set")
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
	// Baseline (file) values for detecting non-reloadable changes later; the
	// running listen/CA address may be overridden by flags below.
	baseline := &config.Config{Listen: cfg.Listen, CA: config.CA{Dir: cfg.CA.Dir}}
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
		"version", version,
		"addr", ln.Addr().String(),
		"ca", authority.CertPath(),
		"rules", len(cfg.Rules))
	if isLoopbackHost(hostOf(cfg.Listen)) {
		log.Info("bound to loopback only (development mode)")
	} else {
		log.Warn("bound to a NON-loopback address; injected credentials are reachable from your network")
	}

	// reload re-reads the config file and atomically applies the rules and
	// cache settings. A bad config is logged and the running config is kept.
	reload := func() {
		newCfg, err := config.Load(*configPath)
		if err != nil {
			log.Error("config reload failed; keeping current config", "err", err)
			return
		}
		if changes := config.NonReloadableChanges(baseline, newCfg); len(changes) > 0 {
			log.Warn("config change needs a restart to take effect",
				"fields", strings.Join(changes, "; "))
		}
		if err := handler.Reload(newCfg); err != nil {
			log.Error("config reload failed; keeping current config", "err", err)
			return
		}
		resolver.SetTTL(newCfg.Cache.TTL.Or(5 * time.Minute))
		baseline = &config.Config{Listen: newCfg.Listen, CA: config.CA{Dir: newCfg.CA.Dir}}
		log.Info("config reloaded", "path", *configPath, "rules", len(newCfg.Rules))
	}

	watchCtx, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()
	interval := time.Duration(0)
	if *watch {
		interval = *reloadInterval
	}
	go watchConfig(watchCtx, log, *configPath, interval, reload)

	idleClosed := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Info("shutting down")
		stopWatch()
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

// watchConfig reloads the config on SIGHUP and, when interval > 0, whenever the
// config file's modification time changes.
func watchConfig(ctx context.Context, log *slog.Logger, path string, interval time.Duration, reload func()) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	var tick <-chan time.Time
	if interval > 0 {
		t := time.NewTicker(interval)
		defer t.Stop()
		tick = t.C
	}
	last := fileModTime(path)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			log.Info("SIGHUP received, reloading config")
			reload()
		case <-tick:
			m := fileModTime(path)
			if m.IsZero() || m.Equal(last) {
				continue
			}
			last = m
			log.Info("config file changed, reloading", "path", path)
			reload()
		}
	}
}

func fileModTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
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
