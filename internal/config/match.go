package config

import "strings"

// MatchHost reports whether hostname matches the glob pattern. A "*" label in
// the pattern matches exactly one host label (it does not cross "."), so
// "*.github.com" matches "api.github.com" but neither "github.com" nor
// "a.b.github.com". Matching is case-insensitive.
func MatchHost(pattern, hostname string) bool {
	pl := strings.Split(strings.ToLower(pattern), ".")
	hl := strings.Split(strings.ToLower(hostname), ".")
	if len(pl) != len(hl) {
		return false
	}
	for i := range pl {
		if pl[i] == "*" {
			if hl[i] == "" {
				return false
			}
			continue
		}
		if pl[i] != hl[i] {
			return false
		}
	}
	return true
}

// Find returns the first rule that matches hostname, or nil if none do.
func (c *Config) Find(hostname string) *Rule {
	for i := range c.Rules {
		for _, pat := range c.Rules[i].Match.Hosts {
			if MatchHost(pat, hostname) {
				return &c.Rules[i]
			}
		}
	}
	return nil
}
