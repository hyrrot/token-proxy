package config

import "testing"

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"api.github.com", "api.github.com", true},
		{"api.github.com", "API.GitHub.com", true},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "github.com", false},
		{"*.github.com", "a.b.github.com", false},
		{"api.github.com", "api.gitlab.com", false},
	}
	for _, c := range cases {
		if got := MatchHost(c.pattern, c.host); got != c.want {
			t.Errorf("MatchHost(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestFindFirstMatchWins(t *testing.T) {
	cfg := &Config{Rules: []Rule{
		{Name: "a", Match: Match{Hosts: []string{"*.example.com"}}},
		{Name: "b", Match: Match{Hosts: []string{"api.example.com"}}},
	}}
	if r := cfg.Find("api.example.com"); r == nil || r.Name != "a" {
		t.Fatalf("Find = %v, want rule a", r)
	}
	if r := cfg.Find("nope.org"); r != nil {
		t.Fatalf("Find = %v, want nil", r)
	}
}
