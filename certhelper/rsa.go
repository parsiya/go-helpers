package certhelper

// RSA certificate helpers.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// RSARootCA returns a self-signed x509 root CA with an RSA key.
func RSARootCA(commonName, orgUnit, serialNumber, countryCode string,
	keySize int) (*x509.Certificate, *rsa.PrivateKey, error) {

	return CustomRSARootCA(commonName, orgUnit, serialNumber, countryCode,
		keySize, CertValidityConstant, MaxPathLenConstant, CAKeyUsageConstant)
}

// CustomRSARootCA returns a custom self-signed x509 CA with an RSA key.
func CustomRSARootCA(commonName, orgUnit, serialNumber, countryCode string,
	keySize, validity, maxPathLen int, keyUsage x509.KeyUsage) (*x509.Certificate, *rsa.PrivateKey, error) {

	// Generate RSA keypair.
	privKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	// Get certificate template.
	tmpl, err := CustomCATemplate(commonName, orgUnit, serialNumber, countryCode,
		"RSA", validity, maxPathLen, keyUsage)
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

// RSALeafCert returns a lead certificate signed by caCert.
func RSALeafCert(commonName, orgUnit, serialNumber, countryCode string,
	keySize int, caCert *x509.Certificate,
	caPrivKey interface{}) (*x509.Certificate, *rsa.PrivateKey, error) {

	return CustomRSALeafCert(commonName, orgUnit, serialNumber, countryCode,
		CertValidityConstant, keySize, caCert, caPrivKey)
}

// CustomRSALeafCert returns a certificate signed by caCert. The certificate
// uses an RSA key. caCert can have any type of key.
func CustomRSALeafCert(commonName, orgUnit, serialNumber, countryCode string,
	validity, keySize int, caCert *x509.Certificate,
	caPrivKey interface{}) (*x509.Certificate, *rsa.PrivateKey, error) {

	// Generate RSA keypair.
	privKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	// Get certificate template.
	tmpl, err := CustomLeafTemplate(commonName, orgUnit, serialNumber,
		countryCode, "RSA", validity, LeafKeyUsageConstant)
	if err != nil {
		return nil, nil, err
	}
	// Parse private key and generate the certificate.
	var certDER []byte
	switch t := caPrivKey.(type) {
	case *rsa.PrivateKey:
		rsaPrivKey, _ := caPrivKey.(*rsa.PrivateKey)
		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, caCert, privKey.Public(), rsaPrivKey)
	case *ecdsa.PrivateKey:
		ecPrivKey, _ := caPrivKey.(*ecdsa.PrivateKey)
		certDER, err = x509.CreateCertificate(rand.Reader, tmpl, caCert, privKey.Public(), ecPrivKey)
	default:
		return nil, nil, fmt.Errorf("invalid caPrivKey, got type %s", t)
	}
	// Check certificate generation errors.
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
