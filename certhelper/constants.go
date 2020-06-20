package certhelper

import "crypto/x509"

// Constants.

var (
	// Certificates are valid for a year.
	CertValidityConstant = 1
	// Leaf certificate key usage.
	LeafKeyUsageConstant = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	// Default max path length is 0.
	MaxPathLenConstant = 0
	// CA key usage.
	CAKeyUsageConstant = x509.KeyUsageCertSign
)
