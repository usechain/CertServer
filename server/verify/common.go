//@Time  : 2018/3/17 12:12
//@Author: Greg Li
package verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"crypto/sha256"
	"crypto/ecdsa"
	"math/big"
	"fmt"
)

func loadPublicKeyFromPemFile(publicKeyFilename string) *rsa.PublicKey {
	fileData, err := ioutil.ReadFile(publicKeyFilename)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(fileData)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("Unable to load valid public key. ")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("Error loading public key. ", err)
	}
	pub := pubInterface.(*rsa.PublicKey)//pub:公钥对象
	return pub
}

func verifyRsaSig(signature []byte, message []byte, publicKey *rsa.PublicKey) bool {

	hashedMessage := sha256.Sum256(message)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedMessage[:], signature, )
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func loadFile(filename string) []byte {
	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	return fileData
}


func VerifyEcdsaSig(addr []byte, pub *ecdsa.PublicKey,r *big.Int,s *big.Int) bool {
	hashedMessage := sha256.Sum256(addr)
	err := ecdsa.Verify(pub, hashedMessage[:],r,s)
	fmt.Println(err)
	return err
}

