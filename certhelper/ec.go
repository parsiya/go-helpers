package certhelper

// EC certificate helpers.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

// ECRootCA returns a self-signed x509 root CA with an EC key.
func ECRootCA(commonName, orgUnit, serialNumber, countryCode string,
	curve string) (*x509.Certificate, *ecdsa.PrivateKey, error) {

	return CustomECRootCA(commonName, orgUnit, serialNumber, countryCode, curve,
		CertValidityConstant, MaxPathLenConstant, CAKeyUsageConstant)
}

// CustomECRootCA returns a custom self-signed x509 root CA with an EC key.
func CustomECRootCA(commonName, orgUnit, serialNumber, countryCode, curve string,
	validity, maxPathLen int,
	keyUsage x509.KeyUsage) (*x509.Certificate, *ecdsa.PrivateKey, error) {

	// Generate EC keypair.
	privKey, err := ECKeys(curve)
	if err != nil {
		return nil, nil, err
	}
	// Get certificate template.
	tmpl, err := CustomCATemplate(commonName, orgUnit, serialNumber, countryCode,
		"EC", validity, maxPathLen, keyUsage)
	if err != nil {
		return nil, nil, err
	}
	// Create certificate's DER bytes.
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privKey.Public(), privKey)
	if err != nil {
		return nil, nil, err
	}
	// Convert DER bytes to *x509.Certificate.
	certParsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return certParsed, privKey, nil
}

// ECLeafCert returns a leaf certificate with an EC key.
func ECLeafCert(commonName, orgUnit, serialNumber, countryCode, curve string,
	caCert *x509.Certificate,
	caPrivKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey, error) {

	return CustomECLeafCert(commonName, orgUnit, serialNumber, countryCode,
		curve, CertValidityConstant, caCert, caPrivKey)
}

// CustomECLeafCert returns a custom leaf certificate with an EC key. Certificate
// signed by caCert with caPrivKey.
func CustomECLeafCert(commonName, orgUnit, serialNumber, countryCode, curve string,
	validity int, caCert *x509.Certificate,
	caPrivKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey, error) {

	// Generate EC keypair.
	privKey, err := ECKeys(curve)
	if err != nil {
		return nil, nil, err
	}
	// Get certificate template.
	tmpl, err := CustomLeafTemplate(commonName, orgUnit, serialNumber,
		countryCode, "EC", validity, LeafKeyUsageConstant)
	if err != nil {
		return nil, nil, err
	}
	// Parse private key and generate the certificate.
	var certDER []byte
	switch k := caPrivKey.(type) {
	case *rsa.PrivateKey:
		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, caCert, privKey.Public(), k)
	case *ecdsa.PrivateKey:
		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, caCert, privKey.Public(), k)
	default:
		return nil, nil, fmt.Errorf("invalid caPrivKey, got %v", k)
	}
	if err != nil {
		return nil, nil, err
	}
	// Convert DER bytes to *x509.Certificate.
	certParsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	return certParsed, privKey, nil
}

// ECKeys returns an EC key pair with a specified curve.
// Valid curves are P224, P256, P384 and P521 (case-insensitive).
// If curve is invalid or empty, P224 is used.
// Go's supported curves: https://golang.org/pkg/crypto/elliptic/#Curve
func ECKeys(curve string) (*ecdsa.PrivateKey, error) {
	switch strings.ToUpper(curve) {
	default:
		fallthrough
	case "P224":
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	}
}
