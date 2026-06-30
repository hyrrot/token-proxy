package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/hyrrot/token-proxy/internal/config"
	"github.com/hyrrot/token-proxy/internal/secrets"
)

// compiledHeader is a header whose value template has been parsed.
type compiledHeader struct {
	name string
	tmpl *template.Template
}

// injector applies a rule's header mutations, resolving secrets at render time.
type injector struct {
	resolver *secrets.Resolver
	rules    map[string][]compiledHeader // keyed by rule name
}

func newInjector(cfg *config.Config, resolver *secrets.Resolver) (*injector, error) {
	inj := &injector{resolver: resolver, rules: map[string][]compiledHeader{}}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		headers := make([]compiledHeader, 0, len(r.Inject.Headers))
		for _, h := range r.Inject.Headers {
			t, err := template.New(r.Name + ":" + h.Name).
				Funcs(stubFuncs()).
				Option("missingkey=error").
				Parse(h.Value)
			if err != nil {
				return nil, fmt.Errorf("rule %q header %q: invalid template: %w", r.Name, h.Name, err)
			}
			headers = append(headers, compiledHeader{name: h.Name, tmpl: t})
		}
		inj.rules[r.Name] = headers
	}
	return inj, nil
}

// apply mutates req's headers according to the named rule. Secret resolution
// uses req's context.
func (in *injector) apply(req *http.Request, ruleName string) error {
	headers := in.rules[ruleName]
	ctx := req.Context()
	for _, h := range headers {
		val, err := in.render(ctx, h.tmpl)
		if err != nil {
			return fmt.Errorf("render header %q: %w", h.name, err)
		}
		req.Header.Set(h.name, val)
	}
	return nil
}

func (in *injector) render(ctx context.Context, t *template.Template) (string, error) {
	var buf bytes.Buffer
	// Rebind the funcs to ones that close over the request context so secret
	// lookups are cancelled if the client goes away.
	err := t.Funcs(in.realFuncs(ctx)).Execute(&buf, nil)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (in *injector) realFuncs(ctx context.Context) template.FuncMap {
	return template.FuncMap{
		"secret": func(ref string) (string, error) {
			return in.resolver.Resolve(ctx, ref)
		},
		"base64": func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(s))
		},
		"trim": strings.TrimSpace,
		"env":  os.Getenv,
	}
}

// stubFuncs provides the same function names at parse time so templates compile
// before the request-bound implementations are available.
func stubFuncs() template.FuncMap {
	return template.FuncMap{
		"secret": func(string) (string, error) { return "", nil },
		"base64": func(string) string { return "" },
		"trim":   strings.TrimSpace,
		"env":    os.Getenv,
	}
}
