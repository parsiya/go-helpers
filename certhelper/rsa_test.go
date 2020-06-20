package certhelper

import (
	"testing"
	"time"
)

// Had to reduce the number of cases, otherwise it would time out even after 10
// minutes. But it works.
func TestCustomRSARootCA(t *testing.T) {
	cNames := []string{"cname1"}
	orgUnits := []string{"orgunit1"}
	serialNumbers := []string{"1"}
	countryCodes := []string{"US"}
	keySizes := []int{1024, 2048, 3072, 4096}
	validities := []int{1}
	maxPathLengths := []int{0, 1}
	keyUsage := CAKeyUsageConstant

	for _, commonName := range cNames {
		for _, orgUnit := range orgUnits {
			for _, serialNumber := range serialNumbers {
				for _, countryCode := range countryCodes {
					for _, keySize := range keySizes {
						for _, validity := range validities {
							for _, maxPathLen := range maxPathLengths {
								// Generate test certificate.
								cert, _, err := CustomRSARootCA(commonName,
									orgUnit, serialNumber, countryCode,
									keySize, validity, maxPathLen, keyUsage)
								// Check for errors.
								if err != nil {
									t.Errorf("Error in CustomECRootCA(%s, %s, %s, %s, %d, %d, %d)",
										commonName, orgUnit, serialNumber,
										countryCode, keySize,
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
