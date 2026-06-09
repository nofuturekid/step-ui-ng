package certs

// parsed_cert.go — derive rich metadata from a stored leaf PEM.
//
// All fields are computed from the already-stored CertPEM; no DB or schema
// change is needed. If the PEM cannot be parsed (should never happen for a
// stored cert) the caller receives a zero ParsedCert and degrade-gracefully:
// the detail page shows the existing fields (CN, SANs, dates, serial) and
// omits the derived ones.
//
// Fingerprint format: plain lowercase hex (no separators), matching the default
// output of "step certificate fingerprint" (sha256(leaf.Raw)).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// ParsedCert holds the fields derived by parsing the leaf PEM at view time.
// All fields are public certificate data — no secrets involved.
type ParsedCert struct {
	// Fingerprint is the SHA-256 of the leaf DER as plain lowercase hex (no
	// separators), matching the default output of "step certificate fingerprint".
	Fingerprint string
	// Issuer is the issuing CA's common name (or full DN if CN is empty).
	Issuer string
	// PublicKeyType is a human-readable description of the public key algorithm
	// and size, e.g. "ECDSA P-256", "RSA 2048", "Ed25519".
	PublicKeyType string
	// KeyUsages is the list of key usage strings (e.g. "digitalSignature",
	// "keyEncipherment"). Empty when no key usages are set on the cert.
	KeyUsages []string
	// ExtKeyUsages is the list of extended key usage strings (e.g. "serverAuth",
	// "clientAuth"). Empty when no EKUs are set on the cert.
	ExtKeyUsages []string
}

// ParseLeafPEM parses certPEM (the leaf certificate PEM block) and returns the
// derived ParsedCert. On any parse failure it returns an empty ParsedCert and
// a non-nil error; callers should degrade gracefully and not propagate the error
// to the user.
func ParseLeafPEM(certPEM string) (ParsedCert, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ParsedCert{}, fmt.Errorf("certs: ParseLeafPEM: no PEM block found")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ParsedCert{}, fmt.Errorf("certs: ParseLeafPEM: %w", err)
	}

	sum := sha256.Sum256(leaf.Raw)
	return ParsedCert{
		Fingerprint:   fingerprintHex(sum[:]),
		Issuer:        issuerName(leaf),
		PublicKeyType: pubKeyType(leaf),
		KeyUsages:     keyUsageStrings(leaf.KeyUsage),
		ExtKeyUsages:  extKeyUsageStrings(leaf.ExtKeyUsage),
	}, nil
}

// fingerprintHex formats raw SHA-256 bytes as plain lowercase hex (no
// separators): e.g. "5b1f9ac2…". Matches "step certificate fingerprint".
func fingerprintHex(raw []byte) string {
	return hex.EncodeToString(raw)
}

// issuerName returns the issuer CN when set, falling back to the full DN.
func issuerName(cert *x509.Certificate) string {
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	return cert.Issuer.String()
}

// pubKeyType returns a human-readable key-algorithm + size string.
func pubKeyType(cert *x509.Certificate) string {
	switch k := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", cert.PublicKey)
	}
}

// keyUsageStrings maps the x509.KeyUsage bitmask to named strings. It follows
// RFC 5280 §4.2.1.3 naming (lower-camelCase as used by OpenSSL and the "step"
// CLI).
func keyUsageStrings(ku x509.KeyUsage) []string {
	type bit struct {
		mask x509.KeyUsage
		name string
	}
	bits := []bit{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var out []string
	for _, b := range bits {
		if ku&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

// extKeyUsageStrings maps []x509.ExtKeyUsage to their RFC 5280 / TLS naming
// strings (lower-camelCase as used by OpenSSL / "step").
func extKeyUsageStrings(ekus []x509.ExtKeyUsage) []string {
	m := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "any",
		x509.ExtKeyUsageServerAuth:                     "serverAuth",
		x509.ExtKeyUsageClientAuth:                     "clientAuth",
		x509.ExtKeyUsageCodeSigning:                    "codeSigning",
		x509.ExtKeyUsageEmailProtection:                "emailProtection",
		x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
		x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
		x509.ExtKeyUsageTimeStamping:                   "timeStamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "msServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscapeServerGatedCrypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "msCommercialCodeSigning",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "msKernelCodeSigning",
	}
	var out []string
	for _, e := range ekus {
		if name, ok := m[e]; ok {
			out = append(out, name)
		}
	}
	return out
}
