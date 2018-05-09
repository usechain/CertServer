//@Time  : 2018/3/27 10:44
//@Author: Greg Li
package handlers

import (
	"net/http"
	"cert_service/server/model"
	"encoding/json"
	"io/ioutil"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/astaxie/beego/logs"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"cert_service/server/generateCA"
	"github.com/ethereum/go-ethereum/crypto"
	"strconv"
)

type SignData struct {
	Sig		string		`json:"sig"`
	Msg  	string		`json:"msg"`
	Addr 	string 		`json:"addr"`
	Pub 	string		`json:"pub"`
}

type Res struct {
	Error string `json:"error"`
	Tcert string `json:"tcert"`
	Msg   string `json:"msg"`
	MainAddrTag string `json:"tag"`
	Lev string `json:"lev"`
}

func TcertHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")             //允许访问所有域
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type") //header的类型
	w.Header().Set("content-type", "application/json")             //返回数据格式是json

	//1.获取数据
	signData := SignData{}
	r.ParseForm()
	if len(r.Form) > 0{
		signData.Pub=r.FormValue("pub")
		signData.Sig=r.FormValue("sig")
		signData.Msg=r.FormValue("msg")
		signData.Addr=r.FormValue("addr")
	}
	if len(r.Form)==0{
		jsn, err := ioutil.ReadAll(r.Body)
		fmt.Println("Received from command line client",string(jsn))
		if err != nil {
			logs.Error("Error reading the body", err)
		}
		err = json.Unmarshal(jsn, &signData)
	}

	recv, err:= json.Marshal(SignData{
		Sig:signData.Sig,
		Msg:signData.Msg,
		Addr:signData.Addr,
		Pub:signData.Pub,
	})
	logs.Info("Received tcert request data: %v\n", string(recv))

	//2.验证pub
	pubdb,err:=model.GetUserPubByPub(signData.Pub)
	if err !=nil {
		fmt.Println(err)
		logs.Error("GetUserPubByName error : ",err)
	}
	levdb,err:=model.GetUserLevByPub(signData.Pub)
	if err !=nil {
		fmt.Println(err)
		logs.Error("GetUserPubLevByName error : ",err)
	}

	if pubdb == nil{
		res, _:= json.Marshal(Res{
			Error:"1",
			Msg:"未知公钥",
		})
		w.Write(res)
		return
	}

	
	//3.验证签名
	msg,err:=hexutil.Decode(signData.Msg)
	if err!=nil{
		fmt.Println(err)
		res, _:= json.Marshal(Res{
			Error:"2",
			Msg:"数据格式错误",
		})
		w.Write(res)
		return
	}

	pubkey,err:= hexutil.Decode(signData.Pub)
	if err!=nil{
		fmt.Println(err)
		res, _:= json.Marshal(Res{
			Error:"2",
			Msg:"数据格式错误",
		})
		w.Write(res)
		return
	}

	sig,err:=hexutil.Decode(signData.Sig)
	if err!=nil{
		fmt.Println(err)
		res, _:= json.Marshal(Res{
			Error:"2",
			Msg:"数据格式错误",
		})
		w.Write(res)
		return
	}

	var result bool
	//fmt.Println(err)
	if err==nil {
		result=secp256k1.VerifySignature(pubkey, msg, sig[:64])
		logs.Info("签名验证结果:",result)
	}

	if result==false{
		res, _:= json.Marshal(Res{
			Error:"3",
			Msg:"签名验证不通过",
		})
		w.Write(res)
		return
	}

	

	//如果签名正确，颁发Tcert
	var tcert string
	if result == true {
		//fmt.Println(levdb[0])
		//存储数据库
		userInfo := &model.UserInfo{}
		if len(signData.Addr)==42{
			userInfo.Addr = signData.Addr
		} else {
			res, _:= json.Marshal(Res{
				Error:"4",
				Tcert:tcert,
				Msg:"请输入42位长度地址",
			})
			w.Write(res)
			return
		}

		tcert =generateCA.GenTcert(signData.Addr,true, "P521",levdb[0],mainAddrTag)
		w.Header().Set("Content-Type", "application/json")

		userInfo.Pub=signData.Pub
		userInfo.MainAddrTag = mainAddrTag
		//fmt.Println(userInfo.MainAddrTag)
		userInfo.Tcert = fmt.Sprintf("%v.tcert",string(signData.Addr))

		useraddr,err:= model.GetUserAddrByAddr(signData.Addr)
		if useraddr ==nil{
			err2 := model.CreateUserInfo(userInfo)
			if err2 != nil {
				logs.Warn("invalid parameter")
			}
		}

		if useraddr !=nil {
			err2 := model.UpdateUserInfo(userInfo)
			if err2 != nil {
				logs.Warn("invalid parameter")
			}
		}

		res, err:= json.Marshal(Res{
			Error:"0",
			Tcert:tcert,
			Msg:"成功获取Tcert",
			MainAddrTag:strconv.Itoa(mainAddrTag),
			Lev:strconv.Itoa(levdb[0]),
		})
		if err !=nil {
			fmt.Println(err)
		}
		//fmt.Fprint(w, string(res))
		w.Write(res)
	}
}
