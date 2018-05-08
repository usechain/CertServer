//@Time  : 2018/3/16 15:23
//@Author: Greg Li
package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"crypto/ecdsa"
	"encoding/base64"
	"math/big"
)

func LoadInfoFromFile(infoFilename string) []byte {
	fileData, err := ioutil.ReadFile(infoFilename)
	if err != nil {
		log.Fatal(err)
	}
	return fileData
}

func LoadRsaPrivKeyFromFile(privateKeyFilename string) *rsa.PrivateKey {

	fileData, err := ioutil.ReadFile(privateKeyFilename)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(fileData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("Unable to load a valid private key.")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Error loading private key.", err)
	}
	return privateKey
}

func LoadECPrivKeyFromFile(privateKeyFilename string) *ecdsa.PrivateKey {

	fileData, err := ioutil.ReadFile(privateKeyFilename)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(fileData)
	if block == nil {
		log.Fatal("Unable to load a valid private key.")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Error loading private key.", err)
	}
	return privateKey
}

func SignRSA(p []byte, s *rsa.PrivateKey) (string, error) {
	hashed := sha256.Sum256(p)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s, crypto.SHA256, hashed[:])
	return base64.StdEncoding.EncodeToString(sig), err
}

func SignECDSABigInt(p []byte, k *ecdsa.PrivateKey) (*big.Int,*big.Int, [32]byte) {
	hashed := sha256.Sum256(p)
	r, s, err := ecdsa.Sign(rand.Reader, k, hashed[:])
	if err != nil {
		log.Fatal(err)
	}
	return r,s, hashed
}

func SignECDSA(p []byte, k *ecdsa.PrivateKey) ([]byte, []byte) {
	hashed := sha256.Sum256(p)
	r, s, _ := ecdsa.Sign(rand.Reader, k, hashed[:])
	return r.Bytes(), s.Bytes()
}
