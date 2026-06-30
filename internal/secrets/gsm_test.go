package secrets

import "testing"

func TestParseGSMRef(t *testing.T) {
	cases := []struct {
		ref                      string
		project, secret, version string
		wantErr                  bool
	}{
		{"gsm://proj/mysecret", "proj", "mysecret", "latest", false},
		{"gsm://proj/mysecret/5", "proj", "mysecret", "5", false},
		{"gsm://proj/mysecret/latest", "proj", "mysecret", "latest", false},
		{"gsm://proj", "", "", "", true},
		{"gsm://proj/", "", "", "", true},
		{"gsm://proj/sec/ver/extra", "", "", "", true},
	}
	for _, c := range cases {
		got, err := parseGSMRef(c.ref)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseGSMRef(%q) = %+v, want error", c.ref, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseGSMRef(%q) error: %v", c.ref, err)
			continue
		}
		if got.project != c.project || got.secret != c.secret || got.version != c.version {
			t.Errorf("parseGSMRef(%q) = %+v, want {%s %s %s}", c.ref, got, c.project, c.secret, c.version)
		}
	}
}

func TestVersionFromName(t *testing.T) {
	if got := versionFromName("projects/p/secrets/s/versions/12"); got != "12" {
		t.Errorf("versionFromName = %q, want 12", got)
	}
}
