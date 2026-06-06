package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// genIntermediateCA produces an intermediate CA signed by root (IsCA, CertSign),
// used so the mock CA returns a non-trivial chain (leaf → intermediate → root).
func genIntermediateCA(t *testing.T, root *keyPair, cn string) *keyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen intermediate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 3),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key)
	if err != nil {
		t.Fatalf("create intermediate cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate cert: %v", err)
	}
	return &keyPair{cert: cert, key: key, der: der}
}

// issueFromCSR signs a leaf certificate from the CSR's public key and subject,
// signed by the intermediate. Returns the leaf PEM and the intermediate PEM
// (the chain element above the leaf).
func issueFromCSR(t *testing.T, csr *x509.CertificateRequest, root, intermediate *keyPair, notAfter time.Time) (leafPEM, chainPEM string) {
	t.Helper()
	_ = root
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano() + 11),
		Subject:        csr.Subject,
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, intermediate.cert, csr.PublicKey, intermediate.key)
	if err != nil {
		t.Fatalf("issue leaf from CSR: %v", err)
	}
	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	chainPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.der}))
	return leafPEM, chainPEM
}

// buildCSR creates a PKCS#10 CSR with the given CN and SANs (DNS/IP/email/URI),
// signed by a freshly generated EC key, returning the CSR PEM and the key PEM.
func buildCSR(t *testing.T, cn string, dns, ips, emails, uris []string) (csrPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen csr key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		DNSNames:       dns,
		EmailAddresses: emails,
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	for _, u := range uris {
		parsed, perr := url.Parse(u)
		if perr != nil {
			t.Fatalf("parse uri %q: %v", u, perr)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal csr key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return csrPEM, keyPEM
}
