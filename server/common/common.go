//@Time  : 2018/3/18 22:19
//@Author: Greg Li
package common

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParseEcaEcdsa(ecert []byte) (*x509.Certificate) {

	ecaBlock, _:= pem.Decode(ecert)
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
