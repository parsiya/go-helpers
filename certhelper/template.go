package certhelper

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// CATemplate returns an x509.Certificate template for a root CA.
// algo can be "RSA" or "EC" (case-insensitive).
// Default values:
//     	validity = CertValidity in constants.go. 1 year.
// 		maxPathLen = 0 - can only sign leaf certificates.
//		keyUsage = x509.KeyUsageCertSign - CAKeyUsageConstant
func CATemplate(commonName, orgUnit, serialNumber, countryCode string,
	algo string) (*x509.Certificate, error) {
	return CustomCATemplate(commonName, orgUnit, serialNumber, countryCode,
		algo, CertValidityConstant, 0, x509.KeyUsageCertSign)
}

// CustomCATemplate returns an x509.Certificate template for a root CA.
// algo must be "RSA" or "EC" (case-insensitive).
// validity is in years. For example, 1.
// if maxPathLen is zero, the certificate can only sign leaf certificates and
// MaxPathLenZero is also set to true.
// keyUsage is a mix of https://golang.org/pkg/crypto/x509/#KeyUsage. For example,
// x509.KeyUsageCertSign | x509.KeyUsageCRLSign.
// For more customization, manually create a https://golang.org/pkg/crypto/x509/#Certificate.
func CustomCATemplate(commonName, orgUnit, serialNumber, countryCode, algo string,
	validity, maxPathLen int, keyUsage x509.KeyUsage) (*x509.Certificate, error) {

	cert := x509.Certificate{
		Subject: pkix.Name{
			CommonName:         commonName,
			Country:            []string{countryCode},
			Organization:       []string{orgUnit},
			OrganizationalUnit: []string{orgUnit},
			SerialNumber:       serialNumber,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().AddDate(validity, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	// Set MaxPathLen.
	cert.MaxPathLen = maxPathLen
	if maxPathLen == 0 {
		cert.MaxPathLenZero = true
	}
	// Set algorithm.
	switch strings.ToUpper(algo) {
	case "EC":
		cert.SignatureAlgorithm = x509.ECDSAWithSHA256
	case "RSA":
		cert.SignatureAlgorithm = x509.SHA256WithRSA
	default:
		return nil, fmt.Errorf("algo must be EC or RSA, got %s", algo)
	}

	// Convert serial number to big int.
	sn, err := strconv.Atoi(serialNumber)
	if err != nil {
		return nil, err
	}
	cert.SerialNumber = big.NewInt(int64(sn))
	return &cert, nil
}

// LeafTemplate returns an x509.Certificate template for a leaf certificate.
func LeafTemplate(commonName, orgUnit, serialNumber, countryCode string,
	algo string) (*x509.Certificate, error) {

	return CustomLeafTemplate(commonName, orgUnit, serialNumber, countryCode,
		algo, CertValidityConstant, LeafKeyUsageConstant)
}

// CustomLeafTemplate returns a custom x509.Certificate template for a leaf certificate.
func CustomLeafTemplate(commonName, orgUnit, serialNumber, countryCode, algo string,
	validity int, keyUsage x509.KeyUsage) (*x509.Certificate, error) {

	cert := x509.Certificate{
		Subject: pkix.Name{
			CommonName:         commonName,
			Country:            []string{countryCode},
			Organization:       []string{orgUnit},
			OrganizationalUnit: []string{orgUnit},
			SerialNumber:       serialNumber,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().AddDate(validity, 0, 0),
		IsCA:                  false,
		BasicConstraintsValid: false,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	// Set algorithm.
	switch strings.ToUpper(algo) {
	case "EC":
		cert.SignatureAlgorithm = x509.ECDSAWithSHA256
	case "RSA":
		cert.SignatureAlgorithm = x509.SHA256WithRSA
	default:
		return nil, fmt.Errorf("algo must be EC or RSA, got %s", algo)
	}

	// Convert serial number to big int.
	sn, err := strconv.Atoi(serialNumber)
	if err != nil {
		return nil, err
	}
	cert.SerialNumber = big.NewInt(int64(sn))
	return &cert, nil
}
