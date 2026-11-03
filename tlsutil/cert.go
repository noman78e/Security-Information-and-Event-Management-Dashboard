// Package tlsutil makes the dashboard available over HTTPS without any
// setup: it creates (and renews) a self-signed certificate for this computer.
//
// A self-signed certificate encrypts the connection, but browsers cannot
// check who issued it, so they show a warning the first time. Compare the
// fingerprint printed at start-up with the one the browser shows to be sure
// you are talking to your own HomeSIEM.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func localIPs() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() && !n.IP.IsLinkLocalMulticast() {
			ips = append(ips, n.IP)
		}
	}
	return ips
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, 32)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Ensure makes sure a usable certificate exists at the two paths and returns
// its SHA-256 fingerprint. An existing one is reused while it is valid for
// at least 30 more days and covers every address this computer has now.
func Ensure(certPath, keyPath string) (string, error) {
	ips := localIPs()
	if pair, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && len(pair.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil &&
			time.Until(leaf.NotAfter) > 30*24*time.Hour && covers(leaf, ips) {
			return fingerprint(leaf.Raw), nil
		}
	}
	return generate(certPath, keyPath, ips)
}

func covers(leaf *x509.Certificate, ips []net.IP) bool {
	for _, ip := range ips {
		if leaf.VerifyHostname(ip.String()) != nil {
			return false
		}
	}
	return true
}

func generate(certPath, keyPath string, ips []net.IP) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return "", err
	}
	names := []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, h)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "HomeSIEM", Organization: []string{"HomeSIEM (self-signed)"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil { // the private key stays private
		return "", fmt.Errorf("cannot write %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", fmt.Errorf("cannot write %s: %w", certPath, err)
	}
	return fingerprint(der), nil
}
