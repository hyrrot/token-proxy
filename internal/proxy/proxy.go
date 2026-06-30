// Package proxy implements the credential-injecting MITM forward proxy.
//
// Clients point HTTP(S)_PROXY at this server and trust the internal CA. Plain
// HTTP requests are proxied directly; HTTPS requests arrive as CONNECT. For a
// CONNECT target that matches a configured rule the connection is intercepted
// (TLS-terminated with a minted certificate), credentials are injected, and the
// request is forwarded upstream over a fresh TLS connection. CONNECT targets
// that match no rule are tunnelled blind — their bytes are never decrypted.
package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hyrrot/token-proxy/internal/ca"
	"github.com/hyrrot/token-proxy/internal/config"
	"github.com/hyrrot/token-proxy/internal/secrets"
)

// Proxy is an http.Handler implementing the forward proxy.
type Proxy struct {
	cfg       *config.Config
	ca        *ca.CA
	injector  *injector
	transport *http.Transport
	log       *slog.Logger
}

// New constructs a Proxy.
func New(cfg *config.Config, authority *ca.CA, resolver *secrets.Resolver, log *slog.Logger) (*Proxy, error) {
	inj, err := newInjector(cfg, resolver)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		cfg:      cfg,
		ca:       authority,
		injector: inj,
		transport: &http.Transport{
			Proxy:                 nil, // never chain to an outer proxy
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		log: log,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP proxies a plain (absolute-URI) HTTP request.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "token-proxy: this is a forwarding proxy; use it as an HTTP proxy", http.StatusBadRequest)
		return
	}
	host := hostname(r.URL.Host)
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopHeaders(outReq.Header)

	rule := p.cfg.Find(host)
	if rule != nil {
		if err := p.injector.apply(outReq, rule.Name); err != nil {
			p.log.Error("inject failed", "host", host, "rule", rule.Name, "err", err)
			http.Error(w, "token-proxy: credential injection failed: "+err.Error(), http.StatusBadGateway)
			return
		}
	}
	p.logRequest("http", outReq.Method, host, outReq.URL.Path, rule)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "token-proxy: upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleConnect handles HTTPS via CONNECT: MITM when the target matches a rule,
// otherwise a blind TCP tunnel.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostport := r.URL.Host // host:port
	host := hostname(hostport)

	clientConn, err := hijack(w)
	if err != nil {
		http.Error(w, "token-proxy: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rule := p.cfg.Find(host)
	if rule == nil {
		p.logRequest("tunnel", "CONNECT", host, "", nil)
		p.tunnel(clientConn, hostport)
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		return
	}
	p.mitm(clientConn, hostport, host, rule)
}

// mitm terminates TLS towards the client and forwards decrypted requests
// upstream with credentials injected.
func (p *Proxy) mitm(clientConn net.Conn, hostport, host string, rule *config.Rule) {
	defer clientConn.Close()

	tlsConn := tls.Server(clientConn, p.ca.ServerConfigForHost(host))
	if err := tlsConn.Handshake(); err != nil {
		p.log.Debug("tls handshake with client failed", "host", host, "err", err)
		return
	}
	defer tlsConn.Close()

	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				p.log.Debug("read intercepted request", "host", host, "err", err)
			}
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = hostport
		req.RequestURI = ""
		removeHopHeaders(req.Header)

		if err := p.injector.apply(req, rule.Name); err != nil {
			p.log.Error("inject failed", "host", host, "rule", rule.Name, "err", err)
			writeStatus(tlsConn, http.StatusBadGateway, "token-proxy: credential injection failed: "+err.Error())
			return
		}
		p.logRequest("https", req.Method, host, req.URL.Path, rule)

		resp, err := p.transport.RoundTrip(req)
		if err != nil {
			p.log.Debug("upstream error", "host", host, "err", err)
			writeStatus(tlsConn, http.StatusBadGateway, "token-proxy: upstream error: "+err.Error())
			return
		}
		removeHopHeaders(resp.Header)
		writeErr := resp.Write(tlsConn)
		resp.Body.Close()
		if writeErr != nil {
			return
		}
		if req.Close || resp.Close {
			return
		}
	}
}

// tunnel blindly copies bytes between the client and upstream without
// decrypting them.
func (p *Proxy) tunnel(clientConn net.Conn, hostport string) {
	defer clientConn.Close()
	upstream, err := net.DialTimeout("tcp", hostport, 30*time.Second)
	if err != nil {
		writeStatus(clientConn, http.StatusBadGateway, "token-proxy: dial upstream: "+err.Error())
		return
	}
	defer upstream.Close()
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, upstream); done <- struct{}{} }()
	<-done
}

func (p *Proxy) logRequest(kind, method, host, path string, rule *config.Rule) {
	attrs := []any{"method", method, "host", host}
	if path != "" {
		attrs = append(attrs, "path", path)
	}
	if rule != nil {
		attrs = append(attrs, "rule", rule.Name, "injected", true)
	}
	p.log.Info(kind, attrs...)
}

// --- helpers ---

func hostname(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func hijack(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection does not support hijacking")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func writeStatus(w io.Writer, code int, body string) {
	resp := http.Response{
		StatusCode: code,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(body + "\n")),
	}
	resp.Write(w)
}

// hopHeaders are removed before forwarding in either direction.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(h http.Header) {
	// Drop any header named in the Connection header first.
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
