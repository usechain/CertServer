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
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"io/ioutil"
	"time"
)

func parseRsa() (rcaCert *x509.Certificate,rcaPrivKey *rsa.PrivateKey) {
	//解析rca证书
	rcaFile, err1 := ioutil.ReadFile("rca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	rcaBlock, _:= pem.Decode(rcaFile)
	if rcaBlock == nil {
		fmt.Println("ecaFile error")
		return
	}

	rcaCert, err2 := x509.ParseCertificate(rcaBlock.Bytes)
	if err2 != nil {
		fmt.Println("ParseCertificate err:", err2)
		return
	}

	//解析rca私钥
	rcaPriv, err3 := ioutil.ReadFile("rca.key")
	if err3 != nil {
		fmt.Println(err3)
		return
	}
	rcaKeyBlock, _ := pem.Decode(rcaPriv)
	if rcaKeyBlock == nil {
		fmt.Println("ecaKeyBlock nil error")
		return
	}

	rcaPrivKey, parseErr := x509.ParsePKCS1PrivateKey(rcaKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println(parseErr)
		return
	}
	return rcaCert,rcaPrivKey
}

func parseECDSA() (rcaCert *x509.Certificate,rcaPrivKey *ecdsa.PrivateKey) {
	//解析rca证书
	rcaFile, err1 := ioutil.ReadFile("rca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	rcaBlock, _:= pem.Decode(rcaFile)
	if rcaBlock == nil {
		fmt.Println("ecaFile error")
		return
	}

	rcaCert, err2 := x509.ParseCertificate(rcaBlock.Bytes)
	if err2 != nil {
		fmt.Println("ParseCertificate err:", err2)
		return
	}

	//解析rca私钥
	rcaPriv, err3 := ioutil.ReadFile("rca.key")
	if err3 != nil {
		fmt.Println(err3)
		return
	}
	rcaKeyBlock, _ := pem.Decode(rcaPriv)
	if rcaKeyBlock == nil {
		fmt.Println("ecaKeyBlock nil error")
		return
	}

	rcaPrivKey, parseErr := x509.ParseECPrivateKey(rcaKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println(parseErr)
		return
	}
	return rcaCert,rcaPrivKey
}

func GenECA(addr string,isCA bool,ecdsaCurve string,caName string,privName string,pubName string) {

	var priv interface{}
	var err error
	var rcaCert *x509.Certificate
	var rcaPrivKey interface{}

	switch ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		rcaCert,rcaPrivKey = parseRsa()
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		rcaCert,rcaPrivKey =parseECDSA()
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		rcaCert,rcaPrivKey =parseECDSA()
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		rcaCert,rcaPrivKey =parseECDSA()
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		rcaCert,rcaPrivKey =parseECDSA()
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
	ecaCert, err := x509.CreateCertificate(rand.Reader, &template, rcaCert,pub, rcaPrivKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	SaveCA(caName,ecaCert)

	savePrivkey(privName,priv)
	if pubName=="" {

	} else {
		savePubPem(pubName,pub)
	}

	ecaCert2, _ := x509.ParseCertificate(ecaCert)
	err = ecaCert2.CheckSignatureFrom(rcaCert)
	log.Println("check ecaCert signature: ", err==nil)
}
