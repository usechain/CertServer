//@Time  : 2018/3/16 14:25
//@Author: Greg Li
package generateCA

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"
	//"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/astaxie/beego/logs"
	"encoding/pem"
)

func GenTcert(addr string,isCA bool,ecdsaCurve string,lev int,mainAddrTag int) (tcert string) {

	var err error
	var tcaCert *x509.Certificate
	var tcaPrivKey interface{}

	switch ecdsaCurve {
	case "":
		tcaCert,tcaPrivKey = parseTcaRsa()
	case "P224":
		tcaCert,tcaPrivKey =parseTcaEcdsa()
	case "P256":
		tcaCert,tcaPrivKey =parseTcaEcdsa()
	case "P384":
		tcaCert,tcaPrivKey =parseTcaEcdsa()
	case "P521":
		tcaCert,tcaPrivKey =parseTcaEcdsa()
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", ecdsaCurve)
		os.Exit(1)
	}
	if err != nil {
		logs.Error("failed to generate private key: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logs.Error("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country: []string{"CN"},
			Organization: []string{"UseChain"},

		},
		NotBefore:time.Unix(1522000000, 0),//2018-03-26 01:46:40 +0800 CST
		NotAfter: time.Now().AddDate(10,0,0),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	//template.DNSNames = append(template.DNSNames, "localhost")
	addr1:=fmt.Sprintf("%v@%v%v.com",addr,lev,mainAddrTag)
	template.EmailAddresses = append(template.EmailAddresses, addr1)

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	pub := publicKey(tcaPrivKey)
	txCert, err := x509.CreateCertificate(rand.Reader, &template, tcaCert, pub, tcaPrivKey)
	if err != nil {
		logs.Error("Failed to create certificate: %s", err)
	}
	filename:=fmt.Sprintf("%v.tcert",addr)
	SaveCA(filename,txCert)

	tCert2, _ := x509.ParseCertificate(txCert)
	err = tCert2.CheckSignatureFrom(tcaCert)
	logs.Debug("check tCert signature: ", err==nil)

	//addr2 := tCert2.EmailAddresses
	//fmt.Println("addr",addr2[0][:42])
	//fmt.Println("level",addr2[0][43:44])
	//fmt.Println("tag",addr2[0][44:45])
	//time1:=tCert2.NotBefore
	//time2:=tCert2.NotAfter
	//fmt.Println(time1)
	//fmt.Println(time2)

	//tcert=hexutil.Encode(tCert)
	txCert2:=pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: txCert})
	txCert3:=fmt.Sprintf("%x",txCert2)
	//fmt.Println(txCert3)
	return txCert3
}
