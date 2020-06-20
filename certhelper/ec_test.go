package certhelper

import (
	e "crypto/elliptic"
	"testing"
	"time"
)

// Based on TestKeyGeneration in ecdsa_test.go
func TestECKeys(t *testing.T) {
	curves := map[string]e.Curve{
		"P224": e.P224(),
		"P256": e.P256(),
		"P384": e.P384(),
		"P521": e.P521(),
		"P123": e.P224(),
		"yolo": e.P224(),
	}

	for curveString, curve := range curves {
		// Generate key.
		priv, err := ECKeys(curveString)
		if err != nil {
			t.Errorf("%s curve error: %s", curveString, err)
			continue
		}
		// Check if generated key is on curve.
		if !curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
			t.Errorf("%s curve error: %s", curveString, err)
			continue
		}
	}
}

func TestCustomECRootCA(t *testing.T) {
	cNames := []string{"cname1", "cname2", "cname3"}
	orgUnits := []string{"orgunit1", "orguni2", "orgunit3"}
	serialNumbers := []string{"1", "2", "3"}
	countryCodes := []string{"US", "CA", "AU"}
	curves := []string{"P224", "P256", "P384", "P512"}
	validities := []int{1, 2, 3}
	maxPathLengths := []int{0, 1, 2}
	keyUsage := CAKeyUsageConstant

	for _, commonName := range cNames {
		for _, orgUnit := range orgUnits {
			for _, serialNumber := range serialNumbers {
				for _, countryCode := range countryCodes {
					for _, curve := range curves {
						for _, validity := range validities {
							for _, maxPathLen := range maxPathLengths {
								// Generate test certificate.
								cert, _, err := CustomECRootCA(commonName,
									orgUnit, serialNumber, countryCode,
									curve, validity, maxPathLen, keyUsage)
								// Check for errors.
								if err != nil {
									t.Errorf("Error in CustomECRootCA(%s, %s, %s, %s, %s, %d, %d)",
										commonName, orgUnit, serialNumber,
										countryCode, curve,
										validity, maxPathLen)
								}
								// Check the generated certificate for values.
								if cert.Subject.CommonName != commonName {
									t.Errorf("CommonName error: got %s, want %s", cert.Subject.CommonName, commonName)
									continue
								}
								if cert.Subject.OrganizationalUnit[0] != orgUnit {
									t.Errorf("OrganizationalUnit error: got %s, want %s", cert.Subject.OrganizationalUnit[0], orgUnit)
									continue
								}
								if cert.Subject.SerialNumber != serialNumber {
									t.Errorf("SerialNumber error: got %s, want %s", cert.Subject.SerialNumber, serialNumber)
									continue
								}
								if cert.Subject.Country[0] != countryCode {
									t.Errorf("CountryCode error: got %s, want %s", cert.Subject.Country[0], countryCode)
									continue
								}
								// NotBefore and NotAfter checks need current time.
								currentTime := time.Now().UTC()
								// Certificate's NotBefore should not be in the future.
								if cert.NotBefore.After(currentTime) {
									t.Errorf("NotBefore error: got %s which is after %s", cert.NotBefore, currentTime)
									continue
								}
								// Certificate's NotAfter should not be after currentTime+caValidity.
								if cert.NotAfter.After(currentTime.AddDate(validity, 0, 0)) {
									t.Errorf("NotAfter error: got %s which is after %s", cert.NotAfter, currentTime.AddDate(validity, 0, 0))
									continue
								}
								// Check MaxPathLen.
								if cert.MaxPathLen != maxPathLen {
									t.Errorf("MaxPathLen error: got %d, want %d", cert.MaxPathLen, maxPathLen)
									continue
								}
							}
						}
					}
				}
			}
		}
	}
}

func TestCustomECLeafCert(t *testing.T) {

	// Create a random CA to sign the leaf certs.
	caCert, caPrivKey, err := ECRootCA("root1", "org1", "1234", "US", "P256")
	if err != nil {
		t.Errorf("error creating root CA: %s", err.Error())
	}

	cNames := []string{"cname1", "cname2", "cname3"}
	orgUnits := []string{"orgunit1", "orguni2", "orgunit3"}
	serialNumbers := []string{"1", "2", "3"}
	countryCodes := []string{"US", "CA", "AU"}
	curves := []string{"P224", "P256", "P384", "P512"}
	validities := []int{1, 2, 3}

	for _, commonName := range cNames {
		for _, orgUnit := range orgUnits {
			for _, serialNumber := range serialNumbers {
				for _, countryCode := range countryCodes {
					for _, curve := range curves {
						for _, validity := range validities {
							// Generate test certificate.
							cert, _, err := CustomECLeafCert(commonName, orgUnit,
								serialNumber, countryCode, curve, validity,
								caCert, caPrivKey)
							// Check for errors.
							if err != nil {
								t.Errorf("Error in CustomECLeafCert(%s, %s, %s, %s, %s, %d)",
									commonName, orgUnit, serialNumber,
									countryCode, curve, validity)
							}
							// Check the generated certificate for values.
							if cert.Subject.CommonName != commonName {
								t.Errorf("CommonName error: got %s, want %s", cert.Subject.CommonName, commonName)
								continue
							}
							if cert.Subject.OrganizationalUnit[0] != orgUnit {
								t.Errorf("OrganizationalUnit error: got %s, want %s", cert.Subject.OrganizationalUnit[0], orgUnit)
								continue
							}
							if cert.Subject.SerialNumber != serialNumber {
								t.Errorf("SerialNumber error: got %s, want %s", cert.Subject.SerialNumber, serialNumber)
								continue
							}
							if cert.Subject.Country[0] != countryCode {
								t.Errorf("CountryCode error: got %s, want %s", cert.Subject.Country[0], countryCode)
								continue
							}
							// NotBefore and NotAfter checks need current time.
							currentTime := time.Now().UTC()
							// Certificate's NotBefore should not be in the future.
							if cert.NotBefore.After(currentTime) {
								t.Errorf("NotBefore error: got %s which is after %s", cert.NotBefore, currentTime)
								continue
							}
							// Certificate's NotAfter should not be after currentTime+caValidity.
							if cert.NotAfter.After(currentTime.AddDate(validity, 0, 0)) {
								t.Errorf("NotAfter error: got %s which is after %s", cert.NotAfter, currentTime.AddDate(validity, 0, 0))
								continue
							}
						}
					}
				}
			}
		}
	}

}
