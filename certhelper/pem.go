package certhelper

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

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
	// Check if file exists.
	if filehelper.FileExists(filename) {
		return fmt.Errorf("file %s already exists", filename)
	}
	// Create the file.
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	// Convert certificate to PEM.
	p, err := CertDERToPEM(certDER)
	if err != nil {
		return err
	}
	// Write PEM bytes to file.
	_, err = f.Write(p)
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
