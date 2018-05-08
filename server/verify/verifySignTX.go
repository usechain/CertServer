//@Time  : 2018/3/14 11:34
//@Author: Greg Li
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"io/ioutil"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func parseTcaEcdsa() (rcaCert *x509.Certificate) {
	//解析tca证书
	tcaFile, err1 := ioutil.ReadFile("tca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	tcaBlock, _:= pem.Decode(tcaFile)
	if tcaBlock == nil {
		fmt.Println("tcaFile error")
		return
	}

	tcaCert, err2 := x509.ParseCertificate(tcaBlock.Bytes)
	if err2 != nil {
		fmt.Println("ParseCertificate err:", err2)
		return
	}
	return tcaCert
}

func checkCert(ecdsaCurve string,txCert string) {

	var tcaCert *x509.Certificate
	var addr []string

	switch ecdsaCurve {
	case "P224":
		tcaCert =parseTcaEcdsa()
	case "P256":
		tcaCert =parseTcaEcdsa()
	case "P384":
		tcaCert =parseTcaEcdsa()
	case "P521":
		tcaCert =parseTcaEcdsa()
	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", ecdsaCurve)
		os.Exit(1)
	}

	//验证签名
	txCert2,err:=hexutil.Decode(txCert)
	if err !=nil {
		fmt.Println(err)
	}

	txCert3, err:= x509.ParseCertificate(txCert2)
	if err != nil {
		fmt.Println("ParseCertificate err:", err)
		return
	}

	res := txCert3.CheckSignatureFrom(tcaCert)
	log.Println("check txCert signature: ", res==nil)

	//解析地址
	addr = txCert3.EmailAddresses
	fmt.Println(addr[0][:42])
}

func main() {
	checkCert("P521","0x3082023f308201a0a00302010202100a733c98482f592ab49741ff4330d5f3300a06082a8648ce3d0403043020310b300906035504061302434e3111300f060355040a1308557365436861696e301e170d3138303332323038333231335a170d3238303332323038333231335a3020310b300906035504061302434e3111300f060355040a1308557365436861696e30819b301006072a8648ce3d020106052b81040023038186000400c4b1008ff8d06afa2b6447a6c8b43a6118e47dfd23753c0e675e47e0a85099951b1f563a1f08f874926ca4cd571633584289dc05642dfe91471c14b31260b716ed011575d59566677409908a3fb2966f59d3aceebbca5a2c5a4ba8be7142cadadd0786ad061e442401f84db4e3b0b154dbb1bbc9ef0ed3df20c183d0074276caef57baa3793077300e0603551d0f0101ff0404030202a4301d0603551d250416301406082b0601050507030106082b06010505070302300f0603551d130101ff040530030101ff30350603551d11042e302c812a307838633630653661343733626564623836396564663061653539393166656362376562646236616565300a06082a8648ce3d04030403818c00308188024201b063e20223bf3db9e619ea24b46310f1e4a9c2c79ea3da4ddf5d01db81bfd6ab3cdf463bd64ca72d7701dab9de8067ea27a9f5a5660cb4142bb444cf597d101e93024201554b95686cbe55611132aa878c38ecaa594b94b2543d95ebcad4b1209f91765ceb7a62ca33996de069580de89bace3486c496b077ef9cfcf96a3930643906bb259")
}
