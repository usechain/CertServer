//@Time  : 2018/3/16 9:29
//@Author: Greg Li
package generateCA

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"io/ioutil"
	"github.com/astaxie/beego/logs"
)

//addr
//isCA
//rsaBits     2048位或者1024位
//ecdsaCurve  椭圆曲线P224, P256, P384, P521

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func SaveCA(caName string,cert []byte ){
	certOut, err := os.Create(caName)
	if err != nil {
		log.Fatalf("failed to open for writing: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	logs.Debug("write ecert to", certOut.Name())
	certOut.Close()
}

func savePrivkey(privName string,priv interface{} )  {
	keyOut, err := os.OpenFile(privName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Print("failed to open key.pem for writing:", err)
		return
	}
	pem.Encode(keyOut, pemBlockForKey(priv))
	keyOut.Close()
	log.Println("write to", keyOut.Name())
}

func savePubPem(pubName string,pub interface{})  {
	pubkey, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Println("MarshalPKIXPublicKey err",err)
		return
	}
	pubOut, err := os.Create(pubName)
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	pem.Encode(pubOut, &pem.Block{Type: "PUBLIC KEY", Bytes: pubkey})
	pubOut.Close()
	log.Println("write to", pubOut.Name())
}

func parseEcaRsa() (ecaCert *x509.Certificate, ecaPrivKey *rsa.PrivateKey) {
	//解析eca证书
	ecaFile, err1 := ioutil.ReadFile("eca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	ecaBlock, _:= pem.Decode(ecaFile)
	if ecaBlock == nil {
		fmt.Println("ecaFile read error")
		return
	}

	ecaCert, err2 := x509.ParseCertificate(ecaBlock.Bytes)
	if err2 != nil {
		fmt.Println("ParseCertificate err:", err2)
		return
	}

	//解析eca私钥
	ecaPriv, err3 := ioutil.ReadFile("eca.key")
	if err3 != nil {
		fmt.Println(err3)
		return
	}
	ecaKeyBlock, _ := pem.Decode(ecaPriv)
	if ecaKeyBlock == nil {
		fmt.Println("ecaKeyBlock nil error")
		return
	}

	ecaPrivKey, parseErr := x509.ParsePKCS1PrivateKey(ecaKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println(parseErr)
		return
	}
	return ecaCert,ecaPrivKey
}

func parseEcaEcdsa() (ecaCert *x509.Certificate,ecaPrivKey *ecdsa.PrivateKey) {
	//解析eca证书
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

	ecaCert, err2 := x509.ParseCertificate(ecaBlock.Bytes)
	if err2 != nil {
		fmt.Println("ParseCertificate err:", err2)
		return
	}

	//解析eca私钥
	ecaPriv, err3 := ioutil.ReadFile("eca.key")
	if err3 != nil {
		fmt.Println(err3)
		return
	}
	ecaKeyBlock, _ := pem.Decode(ecaPriv)
	if ecaKeyBlock == nil {
		fmt.Println("ecaKeyBlock nil error")
		return
	}

	ecaPrivKey, parseErr := x509.ParseECPrivateKey(ecaKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println(parseErr)
		return
	}
	return ecaCert,ecaPrivKey
}

func ParsePub(filname string) (pub interface{}) {

	pubPEM, err3 := ioutil.ReadFile(filname)
	if err3 != nil {
		fmt.Println(err3)
		return
	}

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	/*
		switch pub := pub.(type) {
		case *rsa.PublicKey:
			fmt.Println("pub is of type RSA:", pub)
		case *dsa.PublicKey:
			fmt.Println("pub is of type DSA:", pub)
		case *ecdsa.PublicKey:
			fmt.Println("pub is of type ECDSA:", pub)
		default:
			panic("unknown type of public key")
		}
	*/
	return pub
}

func ParseSignPub(public []byte) (pub interface{},err error) {

	//pubPEM, err3 := ioutil.ReadFile(finame)
	//if err3 != nil {
	//	fmt.Println(err3)
	//	return
	//}

	block, _ := pem.Decode([]byte(public))
	if block == nil {
		fmt.Println("failed to parse PEM block containing the public key")
		return
	}

	pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("failed to parse DER encoded public key: " + err.Error())
		return pub,err
	}
	/*
		switch pub := pub.(type) {
		case *rsa.PublicKey:
			fmt.Println("pub is of type RSA:", pub)
		case *dsa.PublicKey:
			fmt.Println("pub is of type DSA:", pub)
		case *ecdsa.PublicKey:
			fmt.Println("pub is of type ECDSA:", pub)
		default:
			panic("unknown type of public key")
		}
	*/
	return pub,err
}

func parseTcaRsa() (rcaCert *x509.Certificate,rcaPrivKey *rsa.PrivateKey) {
	//解析tca证书
	tcaFile, err1 := ioutil.ReadFile("tca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	tcaBlock, _:= pem.Decode(tcaFile)
	if tcaBlock == nil {
		fmt.Println("ecaFile error")
		return
	}

	tcaCert, err2 := x509.ParseCertificate(tcaBlock.Bytes)
	if err2 != nil {
		fmt.Println("ParseCertificate err:", err2)
		return
	}

	//解析tca私钥
	tcaPriv, err3 := ioutil.ReadFile("tca.key")
	if err3 != nil {
		fmt.Println(err3)
		return
	}
	tcaKeyBlock, _ := pem.Decode(tcaPriv)
	if tcaKeyBlock == nil {
		fmt.Println("ecaKeyBlock nil error")
		return
	}

	tcaPrivKey, parseErr := x509.ParsePKCS1PrivateKey(tcaKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println(parseErr)
		return
	}
	return tcaCert,tcaPrivKey
}

func parseTcaEcdsa() (rcaCert *x509.Certificate,rcaPrivKey *ecdsa.PrivateKey) {
	//解析tca证书
	tcaFile, err1 := ioutil.ReadFile("tca.crt")
	if err1 != nil {
		fmt.Println("ReadFile err:", err1)
		return
	}

	tcaBlock, _:= pem.Decode(tcaFile)
	if tcaBlock == nil {
		fmt.Println("ecaFile error")
		return
	}

	tcaCert, err2 := x509.ParseCertificate(tcaBlock.Bytes)
	if err2 != nil {
		fmt.Println("ParseCertificate err:", err2)
		return
	}

	//解析tca私钥
	tcaPriv, err3 := ioutil.ReadFile("tca.key")
	if err3 != nil {
		fmt.Println(err3)
		return
	}
	tcaKeyBlock, _ := pem.Decode(tcaPriv)
	if tcaKeyBlock == nil {
		fmt.Println("ecaKeyBlock nil error")
		return
	}

	tcaPrivKey, parseErr := x509.ParseECPrivateKey(tcaKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println(parseErr)
		return
	}
	return tcaCert,tcaPrivKey
}

