package ca

import (
	"crypto/x509"
	"os"
	"testing"
)

func TestLeafChainsToCA(t *testing.T) {
	dir := t.TempDir()
	authority, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := authority.LeafFor("api.example.com")
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err := os.ReadFile(authority.CertPath())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("append CA cert")
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{
		DNSName: "api.example.com",
		Roots:   roots,
	}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}
}

func TestLoadOrCreatePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	a1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(a1.cert.Raw) != string(a2.cert.Raw) {
		t.Fatal("reloaded CA differs from persisted CA")
	}
}

func TestLeafCachedByHost(t *testing.T) {
	authority, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := authority.LeafFor("a.example.com")
	b, _ := authority.LeafFor("a.example.com")
	if a != b {
		t.Fatal("expected cached leaf to be reused")
	}
}
