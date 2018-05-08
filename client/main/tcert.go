//@Time  : 2018/3/16 14:22
//@Author: Greg Li
package main

import (
	"net/http"
	"os"
	"io/ioutil"
	"encoding/pem"
	"log"
	"encoding/json"
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type SignData struct {
	Sig		string		`json:"sig"`
	Msg  	string		`json:"msg"`
	Addr 	string 		`json:"addr"`
	Pub 	string		`json:"pub"`
}

func ReqTcert(tcertName string) {
	priv,_:=crypto.HexToECDSA("72bbe857c0e439d41385e64163bc4657f9c6ad4af6be5fd521d64176986b2dcd")
	addr :="0x8c60e6a473bedb869edf0ae5991fecb7ebdb6aee"
	pub:="0x049a292baf13ed3a5cccf0af3b5a8475f44b728ac5c50867e629b3b20418bb5b616fe278dfaccc8bb41b058e6837950d2ecfa10b55d0117e296779a78d091ccabd"
	msg := crypto.Keccak256([]byte(addr))
	priv2:=math.PaddedBigBytes(priv.D, 32)
	sig,err:= secp256k1.Sign(msg,priv2)

	if err != nil {
		fmt.Println("sign error",err)
	}

	sig2:=hexutil.Encode(sig)
	msg2:=hexutil.Encode(msg)
	signdata, err := json.Marshal(SignData{
		Sig:sig2,
		Msg:msg2,
		Addr:addr,
		Pub:pub,
	})
	res, err := http.Post("http://10.30.46.73:8888/tcert", "binary/octet-stream",
		bytes.NewBuffer(signdata))
	if err != nil {
		fmt.Println(err)
	}
	defer res.Body.Close()
	tcert, _ := ioutil.ReadAll(res.Body)
	fmt.Printf("tcert text:%v\n",string(tcert))
	saveCA(tcertName,tcert)
}

func saveCA(caName string,cert []byte ){
	certOut, err := os.Create(caName)
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	certOut.Close()
	log.Println("write to", certOut.Name())
}

func main(){
	ReqTcert("tcert222222.crt")
}
