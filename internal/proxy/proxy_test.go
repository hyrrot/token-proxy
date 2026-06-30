package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/hyrrot/token-proxy/internal/ca"
	"github.com/hyrrot/token-proxy/internal/config"
	"github.com/hyrrot/token-proxy/internal/secrets"
)

// staticSource is a trivial secret source for tests: ref "kv://name" returns
// the configured value.
type staticSource struct{ value string }

func (s staticSource) Scheme() string { return "kv" }
func (s staticSource) Fetch(ctx context.Context, ref string) (secrets.Secret, error) {
	return secrets.Secret{Value: s.value, Immutable: true}, nil
}
func (s staticSource) Version(ctx context.Context, ref string) (string, error) {
	return "", secrets.ErrVersionCheckUnsupported
}

func newTestProxy(t *testing.T, cfg *config.Config, upstreamTLS *tls.Config) (*Proxy, *ca.CA) {
	t.Helper()
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resolver := secrets.NewResolver(time.Minute)
	resolver.Register(staticSource{value: "s3cr3t-token"})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New(cfg, authority, resolver, log)
	if err != nil {
		t.Fatal(err)
	}
	// Trust the upstream test server's self-signed cert.
	p.transport.TLSClientConfig = upstreamTLS
	return p, authority
}

func caPool(t *testing.T, authority *ca.CA) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(authority.CertPath())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("failed to load CA cert")
	}
	return pool
}

// clientThroughProxy returns an http.Client that routes via proxyURL and trusts
// the proxy's internal CA.
func clientThroughProxy(t *testing.T, proxyURL string, authority *ca.CA) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{RootCAs: caPool(t, authority)},
		},
	}
}

func startProxy(t *testing.T, p *Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: p}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	return "http://" + ln.Addr().String()
}

func TestMITMInjectsHeaderOverHTTPS(t *testing.T) {
	// Upstream echoes the Authorization header it received.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Auth", r.Header.Get("Authorization"))
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	host := hostname(upstream.Listener.Addr().String())
	cfg := &config.Config{
		Rules: []config.Rule{{
			Name:  "echo",
			Match: config.Match{Hosts: []string{host}},
			Inject: config.Inject{Headers: []config.Header{
				{Name: "Authorization", Value: `Bearer {{ secret "kv://token" }}`},
			}},
		}},
	}

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	p, authority := newTestProxy(t, cfg, &tls.Config{RootCAs: upstreamPool})

	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, authority)

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Saw-Auth"); got != "Bearer s3cr3t-token" {
		t.Fatalf("upstream saw Authorization = %q; want injected token", got)
	}
}

func TestNonMatchingHostIsTunnelledWithoutInjection(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Auth", r.Header.Get("Authorization"))
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	// Rule matches a different host, so this request must be blind-tunnelled.
	cfg := &config.Config{
		Rules: []config.Rule{{
			Name:   "other",
			Match:  config.Match{Hosts: []string{"example.invalid"}},
			Inject: config.Inject{Headers: []config.Header{{Name: "Authorization", Value: "Bearer x"}}},
		}},
	}
	p, authority := newTestProxy(t, cfg, nil)
	proxyURL := startProxy(t, p)

	// For a blind tunnel the client must trust the *upstream's* cert directly,
	// because the proxy never substitutes its own.
	u, _ := url.Parse(proxyURL)
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
	_ = authority

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Saw-Auth"); got != "" {
		t.Fatalf("tunnelled request must not be injected, saw Authorization = %q", got)
	}
}

func TestPlainHTTPInjection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Auth", r.Header.Get("Authorization"))
	}))
	defer upstream.Close()

	host := hostname(upstream.Listener.Addr().String())
	cfg := &config.Config{
		Rules: []config.Rule{{
			Name:   "echo",
			Match:  config.Match{Hosts: []string{host}},
			Inject: config.Inject{Headers: []config.Header{{Name: "Authorization", Value: `Bearer {{ secret "kv://token" }}`}}},
		}},
	}
	p, authority := newTestProxy(t, cfg, nil)
	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, authority)

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Saw-Auth"); got != "Bearer s3cr3t-token" {
		t.Fatalf("plain HTTP injection: Authorization = %q", got)
	}
}
