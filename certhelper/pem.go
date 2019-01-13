package certhelper

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/parsiya/go-utils/filehelper"
)

// CertDERToPEM converts a DER certificate to PEM.
func CertDERToPEM(certDER []byte) (certPEM []byte, err error) {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	if err := pem.Encode(bytes.NewBuffer(certPEM), pemBlock); err != nil {
		return nil, err
	}
	return certPEM, nil
}

// CertDERToPEMFile converts a DER certificate to PEM and stores it in a file.
func CertDERToPEMFile(certDER []byte, filename string) error {
	// Convert certificate to PEM.
	p, err := CertDERToPEM(certDER)
	if err != nil {
		return err
	}
	// Do not overwrite the file.
	err = filehelper.WriteFile(p, filename, false)
	if err != nil {
		return err
	}
	return nil
}

// CertToPEM converts cert *x509.Certificate to PEM.
func CertToPEM(cert *x509.Certificate) ([]byte, error) {
	// Convert certificate to DER.
	return CertDERToPEM(cert.Raw)
}

// CertToPEMFile converts cert *x509.Certificate to PEM and stores it in a file.
func CertToPEMFile(cert *x509.Certificate, filename string) ([]byte, error) {
	return nil, CertDERToPEMFile(cert.Raw, filename)
}

// KeyToPEM converts a private key (RSA or EC) to PEM.
func KeyToPEM(privKey interface{}) (keyPEM []byte, err error) {
	// Adapted from pemBlockForKey at
	// https://golang.org/src/crypto/tls/generate_cert.go.

	var pemBlock pem.Block
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pemBlock.Type = "RSA PRIVATE KEY"
		pemBlock.Bytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal ECDSA private key: %s", err.Error())
		}
		pemBlock.Type = "EC PRIVATE KEY"
		pemBlock.Bytes = b
	default:
		return nil, fmt.Errorf("unknown private key type, got %v", k)
	}
	if err = pem.Encode(bytes.NewBuffer(keyPEM), &pemBlock); err != nil {
		return nil, err
	}
	return keyPEM, nil
}

// KeyToPEMFile converts a private key to PEM and stores it in a file.
func KeyToPEMFile(privKey interface{}, filename string) error {
	// Convert the key to PEM.
	p, err := KeyToPEM(privKey)
	if err != nil {
		return err
	}
	err = filehelper.WriteFile(p, filename, false)
	if err != nil {
		return err
	}
	return nil
}
