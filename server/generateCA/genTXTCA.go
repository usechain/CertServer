//@Time  : 2018/3/13 11:43
//@Author: Greg Li
package generateCA

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func GenTXTCA(addr string,isCA bool,ecdsaCurve string,caName string,privName string,pubName string) {

	var priv interface{}
	var err error
	var tcaCert *x509.Certificate
	var tcaPrivKey interface{}

	switch ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		tcaCert,tcaPrivKey = parseTcaRsa()
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		tcaCert,tcaPrivKey =parseTcaEcdsa()
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tcaCert,tcaPrivKey =parseTcaEcdsa()
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		tcaCert,tcaPrivKey =parseTcaEcdsa()
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		tcaCert,tcaPrivKey =parseTcaEcdsa()
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
	template.EmailAddresses = append(template.EmailAddresses, addr)

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	pub:=publicKey(priv)
	txCert, err := x509.CreateCertificate(rand.Reader, &template, tcaCert, pub, tcaPrivKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	SaveCA(caName,txCert)

	savePrivkey(privName,priv)
	if pubName=="" {

	} else {
		savePubPem(pubName,pub)
	}

	txCert2, _ := x509.ParseCertificate(txCert)
	err = txCert2.CheckSignatureFrom(tcaCert)
	log.Println("check txCert signature: ", err==nil)
}