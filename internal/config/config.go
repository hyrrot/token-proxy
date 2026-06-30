// Package config loads and validates the token-proxy configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration.
type Config struct {
	// Listen is the address the proxy binds to. Defaults to 127.0.0.1:8080.
	Listen string `yaml:"listen"`

	CA    CA    `yaml:"ca"`
	Cache Cache `yaml:"cache"`

	// Rules are evaluated in order; the first rule whose host matcher matches
	// the request host wins.
	Rules []Rule `yaml:"rules"`
}

// CA configures the on-disk location of the internal certificate authority.
type CA struct {
	// Dir is where ca-cert.pem and ca-key.pem are stored/created.
	Dir string `yaml:"dir"`
}

// Cache configures secret caching behaviour.
type Cache struct {
	// TTL is how long a cached secret is served before it is revalidated
	// against its source. Defaults to 5m.
	TTL Duration `yaml:"ttl"`
}

// Rule maps a set of hosts to a set of headers to inject.
type Rule struct {
	Name   string `yaml:"name"`
	Match  Match  `yaml:"match"`
	Inject Inject `yaml:"inject"`
}

// Match selects which requests a rule applies to.
type Match struct {
	// Hosts are glob patterns matched against the request hostname, e.g.
	// "api.github.com" or "*.github.com".
	Hosts []string `yaml:"hosts"`
}

// Inject describes the mutations applied to a matched request.
type Inject struct {
	Headers []Header `yaml:"headers"`
}

// Header is a single header to set on the outbound request. Value is a Go
// text/template string with access to the secret/base64/trim/env functions.
type Header struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// Duration is a time.Duration that unmarshals from a string such as "5m".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Or returns the duration, or def when the duration is zero.
func (d Duration) Or(def time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return time.Duration(d)
}

// Load reads, parses and validates the config file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) normalize() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.CA.Dir == "" {
		c.CA.Dir = DefaultCADir()
	}
	dir, err := expandUser(c.CA.Dir)
	if err != nil {
		return err
	}
	c.CA.Dir = dir
	return nil
}

func (c *Config) validate() error {
	names := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Name == "" {
			return fmt.Errorf("rule %d: name is required", i)
		}
		if names[r.Name] {
			return fmt.Errorf("duplicate rule name %q", r.Name)
		}
		names[r.Name] = true
		if len(r.Match.Hosts) == 0 {
			return fmt.Errorf("rule %q: match.hosts must not be empty", r.Name)
		}
		if len(r.Inject.Headers) == 0 {
			return fmt.Errorf("rule %q: inject.headers must not be empty", r.Name)
		}
		for j, h := range r.Inject.Headers {
			if h.Name == "" {
				return fmt.Errorf("rule %q: header %d: name is required", r.Name, j)
			}
			if h.Value == "" {
				return fmt.Errorf("rule %q: header %q: value is required", r.Name, h.Name)
			}
		}
	}
	return nil
}

// DefaultCADir returns the default CA directory under the user's config dir.
func DefaultCADir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "token-proxy")
	}
	return filepath.Join(".", ".token-proxy")
}

func expandUser(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand %q: %w", path, err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}
