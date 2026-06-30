// Package ca implements token-proxy's internal certificate authority. It loads
// or creates a long-lived root CA on disk and mints short-lived leaf
// certificates on demand so that intercepted HTTPS connections present a
// certificate that is valid under the root CA the client has been told to
// trust.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	certFile = "ca-cert.pem"
	keyFile  = "ca-key.pem"
)

// CA is the internal certificate authority.
type CA struct {
	dir  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// CertPath returns the path of the PEM-encoded root certificate.
func (c *CA) CertPath() string { return filepath.Join(c.dir, certFile) }

// LoadOrCreate loads the CA from dir, creating (and persisting) a new one if it
// does not yet exist.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}
	c := &CA{dir: dir, leaves: map[string]*tls.Certificate{}}

	certPEM, certErr := os.ReadFile(c.CertPath())
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, keyFile))
	if certErr == nil && keyErr == nil {
		if err := c.load(certPEM, keyPEM); err != nil {
			return nil, err
		}
		return c, nil
	}
	if !os.IsNotExist(certErr) && certErr != nil {
		return nil, fmt.Errorf("read ca cert: %w", certErr)
	}
	if err := c.generate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CA) load(certPEM, keyPEM []byte) error {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("%s: not a PEM certificate", c.CertPath())
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("ca key: not a PEM block")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca key: %w", err)
	}
	c.cert = cert
	c.key = key
	return nil
}

func (c *CA) generate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "token-proxy local CA",
			Organization: []string{"token-proxy"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := c.persist(der, key); err != nil {
		return err
	}
	c.cert = cert
	c.key = key
	return nil
}

func (c *CA) persist(certDER []byte, key *ecdsa.PrivateKey) error {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(c.CertPath(), certPEM, 0o644); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(c.dir, keyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}
	return nil
}

// LeafFor returns a leaf certificate valid for host, minting and caching it on
// first use.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.leaves[host]; ok {
		return cert, nil
	}
	cert, err := c.mint(host)
	if err != nil {
		return nil, err
	}
	c.leaves[host] = cert
	return cert, nil
}

func (c *CA) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		// Keep leaves short-lived; they are regenerated on restart anyway.
		NotAfter:              now.AddDate(0, 0, 90),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("mint leaf for %s: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        nil,
	}, nil
}

// ServerConfigForHost returns a *tls.Config that serves a minted certificate
// based on the client's SNI, falling back to fallbackHost when SNI is absent.
func (c *CA) ServerConfigForHost(fallbackHost string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hi.ServerName
			if name == "" {
				name = fallbackHost
			}
			return c.LeafFor(name)
		},
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
