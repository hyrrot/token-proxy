package secrets

import (
	"context"
	"fmt"
	"strings"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// GSM resolves Google Secret Manager references of the form:
//
//	gsm://PROJECT/SECRET            (resolves the "latest" version)
//	gsm://PROJECT/SECRET/VERSION    (a pinned numeric version, immutable)
//
// Credentials come from Application Default Credentials (ADC): a service
// account key file pointed to by GOOGLE_APPLICATION_CREDENTIALS, `gcloud auth
// application-default login`, or the metadata server.
//
// Billing minimisation: a pinned numeric version is immutable, so it is fetched
// once and cached forever. For "latest", the resolver's revalidation calls
// Version, which uses the cheaper GetSecretVersion metadata call to learn the
// current numeric version; the billed AccessSecretVersion read is only repeated
// when that number actually changes.
type GSM struct {
	once    sync.Once
	client  *secretmanager.Client
	initErr error

	// newClient is overridable in tests.
	newClient func(ctx context.Context) (*secretmanager.Client, error)
}

// NewGSM returns a Google Secret Manager source. The underlying client is
// created lazily on first use, so configuring GSM rules costs nothing until a
// gsm:// reference is actually resolved.
func NewGSM() *GSM {
	return &GSM{newClient: func(ctx context.Context) (*secretmanager.Client, error) {
		return secretmanager.NewClient(ctx)
	}}
}

func (s *GSM) Scheme() string { return "gsm" }

func (s *GSM) clientFor(ctx context.Context) (*secretmanager.Client, error) {
	s.once.Do(func() {
		s.client, s.initErr = s.newClient(ctx)
	})
	if s.initErr != nil {
		return nil, fmt.Errorf("init Secret Manager client: %w", s.initErr)
	}
	return s.client, nil
}

type gsmRef struct {
	project string
	secret  string
	version string // "latest" or a numeric version
}

func (r gsmRef) name() string {
	return fmt.Sprintf("projects/%s/secrets/%s/versions/%s", r.project, r.secret, r.version)
}

func parseGSMRef(ref string) (gsmRef, error) {
	rest := strings.TrimPrefix(ref, "gsm://")
	parts := strings.Split(rest, "/")
	switch len(parts) {
	case 2:
		if parts[0] == "" || parts[1] == "" {
			break
		}
		return gsmRef{project: parts[0], secret: parts[1], version: "latest"}, nil
	case 3:
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			break
		}
		return gsmRef{project: parts[0], secret: parts[1], version: parts[2]}, nil
	}
	return gsmRef{}, fmt.Errorf("invalid gsm reference %q: want gsm://PROJECT/SECRET[/VERSION]", ref)
}

func (s *GSM) Fetch(ctx context.Context, ref string) (Secret, error) {
	parsed, err := parseGSMRef(ref)
	if err != nil {
		return Secret{}, err
	}
	client, err := s.clientFor(ctx)
	if err != nil {
		return Secret{}, err
	}
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: parsed.name(),
	})
	if err != nil {
		return Secret{}, fmt.Errorf("access %s: %w", parsed.name(), err)
	}
	return Secret{
		Value: string(resp.GetPayload().GetData()),
		// resp.Name resolves "latest" to the concrete numeric version.
		Version:   versionFromName(resp.GetName()),
		Immutable: parsed.version != "latest",
	}, nil
}

func (s *GSM) Version(ctx context.Context, ref string) (string, error) {
	parsed, err := parseGSMRef(ref)
	if err != nil {
		return "", err
	}
	if parsed.version != "latest" {
		// Pinned versions are immutable; report the number without any call.
		return parsed.version, nil
	}
	client, err := s.clientFor(ctx)
	if err != nil {
		return "", err
	}
	v, err := client.GetSecretVersion(ctx, &secretmanagerpb.GetSecretVersionRequest{
		Name: parsed.name(),
	})
	if err != nil {
		return "", fmt.Errorf("describe %s: %w", parsed.name(), err)
	}
	return versionFromName(v.GetName()), nil
}

func versionFromName(name string) string {
	if i := strings.LastIndex(name, "/versions/"); i >= 0 {
		return name[i+len("/versions/"):]
	}
	return name
}
