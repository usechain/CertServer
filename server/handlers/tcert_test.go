//@Time  : 2018/3/27 10:47
//@Author: Greg Li
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"github.com/jmoiron/sqlx"
	"cert_service/server/model"
	"log"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"bytes"
)

func init(){

	database, err := sqlx.Open("mysql", "root:*******@tcp(127.0.0.1:3306)/certserver")
	if err != nil {
		log.Fatal("open mysql failed,", err)
		return
	}
	model.InitDb(database)
	return
}

func TestVerifyHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/verify", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(VerifyHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "您已验证通过"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	} else {
		fmt.Println("TestVerifyHandler true")
	}
}

type Tdata struct {
	Sig string `json:"sig"`
	Msg string `json:"sig"`
	Addr string `json:"sig"`
	Pub string `json:"sig"`
}

func TestTcertHandler(t *testing.T) {
	tdata, err:= json.Marshal(Tdata{
		Sig: "0xa022dd1467bb11cd2ed7b5f6be6e42ecf1c1e4ec01974570deafc033e2dc1f2367c8072192be0b394b58df6379fabf17cfa62edc415ba3a7c29a3505c87a4e7a00",
		Msg: "0x99c572aaf84fc4ffcccd9314445ab827d2e892006f40e72817e2d4be1db61ee1",
		Addr: "0x8c60e6a473bedb869edf0ae5991fecb7ebdb6aee",
		Pub: "0x049a292baf13ed3a5cccf0af3b5a8475f44b728ac5c50867e629b3b20418bb5b616fe278dfaccc8bb41b058e6837950d2ecfa10b55d0117e296779a78d091ccabd",
	})
	req, err := http.NewRequest("GET", "/tcert", bytes.NewBuffer(tdata))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(TcertHandler)

	handler.ServeHTTP(rr, req)

	SignData := SignData{}
	req.ParseForm()
	if len(req.Form) > 0{
		SignData.Pub=req.FormValue("pub")
		SignData.Sig=req.FormValue("sig")
		SignData.Msg=req.FormValue("msg")
		SignData.Addr=req.FormValue("addr")
	}
	if len(req.Form)==0{
		jsn, err := ioutil.ReadAll(req.Body)
		fmt.Println("jsn------------",string(jsn))
		if err != nil {
			log.Fatal("Error reading the body", err)
		}
		err = json.Unmarshal(jsn, &SignData)
	}

}
