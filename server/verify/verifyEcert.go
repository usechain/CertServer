//@Time  : 2018/3/18 21:36
//@Author: Greg Li
package verify

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"io/ioutil"
)

func parseEcaRsa() (rcaCert *x509.Certificate) {
	ecaFile, err1 := ioutil.ReadFile("eca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	ecaBlock, _:= pem.Decode(ecaFile)
	if ecaBlock == nil {
		fmt.Println("ecaFile error")
		return
	}

	ecaCert, err := x509.ParseCertificate(ecaBlock.Bytes)
	if err != nil {
		fmt.Println("ParseCertificate err:", err)
		return
	}
	return ecaCert
}

func parseEcaEcdsa() (*x509.Certificate) {
	ecaFile, err1 := ioutil.ReadFile("eca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return nil
	}

	ecaBlock, _:= pem.Decode(ecaFile)
	if ecaBlock == nil {
		fmt.Println("ecaFile error")
		return nil
	}

	ecaCert, err2 := x509.ParseCertificate(ecaBlock.Bytes)
	if err2 != nil {
		fmt.Println("ParseCertificate err:", err2)
		return nil
	}
	return ecaCert
}

func CheckEcert(eCert *x509.Certificate,ecdsaCurve string) bool{

	var ecaCert *x509.Certificate

	switch ecdsaCurve {
	case "":
		ecaCert = parseEcaRsa()
	case "P224":
		ecaCert =parseEcaEcdsa()
	case "P256":
		ecaCert =parseEcaEcdsa()
	case "P384":
		ecaCert=parseEcaEcdsa()
	case "P521":
		ecaCert=parseEcaEcdsa()
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", ecdsaCurve)
		os.Exit(1)
	}

	//验证签名
	err := eCert.CheckSignatureFrom(ecaCert)
	log.Println("check eCert signature: ", err==nil)
	return err==nil
}
