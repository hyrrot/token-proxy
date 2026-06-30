package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyrrot/token-proxy/internal/config"
)

// TestReloadChangesInjectionAtRuntime verifies that Proxy.Reload swaps the
// rules used for live requests without recreating the proxy.
func TestReloadChangesInjectionAtRuntime(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Saw-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Saw-Extra", r.Header.Get("X-Extra"))
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	host := hostname(upstream.Listener.Addr().String())

	ruleV1 := config.Rule{
		Name:   "echo",
		Match:  config.Match{Hosts: []string{host}},
		Inject: config.Inject{Headers: []config.Header{{Name: "Authorization", Value: "v1"}}},
	}
	cfgV1 := &config.Config{Rules: []config.Rule{ruleV1}}

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	p, authority := newTestProxy(t, cfgV1, &tls.Config{RootCAs: upstreamPool})
	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, authority)

	// Before reload: v1 header value, no extra header.
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Saw-Auth"); got != "v1" {
		t.Fatalf("before reload: Authorization = %q, want v1", got)
	}
	if got := resp.Header.Get("X-Saw-Extra"); got != "" {
		t.Fatalf("before reload: unexpected X-Extra = %q", got)
	}

	// Hot reload with a changed value and an additional header.
	cfgV2 := &config.Config{Rules: []config.Rule{{
		Name:  "echo",
		Match: config.Match{Hosts: []string{host}},
		Inject: config.Inject{Headers: []config.Header{
			{Name: "Authorization", Value: "v2"},
			{Name: "X-Extra", Value: "added"},
		}},
	}}}
	if err := p.Reload(cfgV2); err != nil {
		t.Fatal(err)
	}

	// Use a fresh client so the request is not served on a kept-alive
	// connection from before the reload.
	client2 := clientThroughProxy(t, proxyURL, authority)
	resp2, err := client2.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if got := resp2.Header.Get("X-Saw-Auth"); got != "v2" {
		t.Fatalf("after reload: Authorization = %q, want v2", got)
	}
	if got := resp2.Header.Get("X-Saw-Extra"); got != "added" {
		t.Fatalf("after reload: X-Extra = %q, want added", got)
	}
}

// TestReloadRejectsBadConfigKeepsRunning verifies a failed reload leaves the
// previous config in place.
func TestReloadRejectsBadConfigKeepsRunning(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{
		Name:   "ok",
		Match:  config.Match{Hosts: []string{"example.com"}},
		Inject: config.Inject{Headers: []config.Header{{Name: "Authorization", Value: "good"}}},
	}}}
	p, _ := newTestProxy(t, cfg, nil)

	// A template that fails to parse must be rejected by Reload.
	bad := &config.Config{Rules: []config.Rule{{
		Name:   "broken",
		Match:  config.Match{Hosts: []string{"example.com"}},
		Inject: config.Inject{Headers: []config.Header{{Name: "Authorization", Value: "{{ .Unterminated"}}},
	}}}
	if err := p.Reload(bad); err == nil {
		t.Fatal("Reload accepted an invalid template")
	}
	if got := p.snap().cfg.Rules[0].Name; got != "ok" {
		t.Fatalf("after failed reload, active rule = %q, want ok", got)
	}
}
