package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureCreatesAndReusesCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")

	fp1, err := Ensure(cert, key)
	if err != nil || len(fp1) != 95 { // 32 bytes as AA:BB:... = 95 characters
		t.Fatalf("first call: %q, %v", fp1, err)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("the files must form a valid pair: %v", err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if leaf.VerifyHostname("127.0.0.1") != nil || leaf.VerifyHostname("localhost") != nil {
		t.Fatal("the certificate must cover localhost")
	}
	if info, _ := os.Stat(key); info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("the private key must not be readable by others: %v", info.Mode())
	}

	fp2, err := Ensure(cert, key)
	if err != nil || fp2 != fp1 {
		t.Fatalf("a valid certificate must be reused: %q vs %q (%v)", fp2, fp1, err)
	}

	os.Remove(key) // broken pair: a new certificate is made
	fp3, err := Ensure(cert, key)
	if err != nil || fp3 == fp1 {
		t.Fatalf("a broken certificate must be replaced: %v", err)
	}
}
