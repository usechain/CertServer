//@Time  : 2018/3/15 15:59
//@Author: Greg Li
package generateCA

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func GenEcert(isCA bool,ecdsaCurve string,caName string,pub interface{}) (eCert []byte) {

	var err error
	var ecaCert *x509.Certificate
	var ecaPrivKey interface{}

	switch ecdsaCurve {
	case "":
		ecaCert,ecaPrivKey = parseEcaRsa()
	case "P224":
		ecaCert,ecaPrivKey =parseEcaEcdsa()
	case "P256":
		ecaCert,ecaPrivKey =parseEcaEcdsa()
	case "P384":
		ecaCert,ecaPrivKey =parseEcaEcdsa()
	case "P521":
		ecaCert,ecaPrivKey =parseEcaEcdsa()
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", ecdsaCurve)
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country: []string{"CN"},
			Organization: []string{"UseChain"},
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(10,0,0),

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	template.DNSNames = append(template.DNSNames, "localhost")
	//template.EmailAddresses = append(template.EmailAddresses, addr)

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	eCert, err = x509.CreateCertificate(rand.Reader, &template, ecaCert, pub, ecaPrivKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	SaveCA(caName,eCert)

	eCert2, _ := x509.ParseCertificate(eCert)
	err = eCert2.CheckSignatureFrom(ecaCert)
	log.Println("check Ecert signature: ", err==nil)
	return eCert
}