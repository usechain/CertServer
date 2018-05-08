//@Time  : 2018/3/15 15:59
//@Author: Greg Li
package main

import (
	"net/http"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type UserPub struct {
	Sig		string   `db:"sig"`
	Pub		string 	`db:"pub"`
}

func verify() {
	publicdata, err := json.Marshal(UserPub{
		Sig:"asdgf",
		Pub:"0x049a292baf13ed3a5cccf0af3b5a8475f44b728ac5c50867e629b3b20418bb5b616fe278dfaccc8bb41b058e6837950d2ecfa10b55d0117e296779a78d091ccabd",
	})
	res, err := http.Post("http://10.30.46.73:8888/verify", "binary/octet-stream",
		bytes.NewBuffer(publicdata))
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()
	data, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(data))
}

func main(){
	verify()
}