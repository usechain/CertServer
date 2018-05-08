//@Time  : 2018/3/31 21:59
//@Author: Greg Li
package handlers

import (
	"net/http"
	"cert_service/server/model"
	"encoding/json"
	"io/ioutil"
	_ "github.com/go-sql-driver/mysql"
	"github.com/astaxie/beego/logs"
	"strconv"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Ret struct {
	Error string `json:"error"`
	Msg   string `json:"msg"`
}

type VerifyInfo struct {
	Sig		string	`json:"sig"`
	Msg		string	`json:"msg"`
	Pub		string	`json:"pub"`
	Lev 	string  `json:"lev"`
}

func VerifyHandler(w http.ResponseWriter, r *http.Request){
	w.Header().Set("Access-Control-Allow-Origin", "*")             //允许访问所有域
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type") //header的类型
	w.Header().Set("content-type", "application/json")             //返回数据格式是json

	VerifyData := VerifyInfo{}
	r.ParseForm()
	if len(r.Form) > 0{
		VerifyData.Pub=r.FormValue("pub")
		VerifyData.Sig=r.FormValue("sig")
		VerifyData.Msg=r.FormValue("msg")
		VerifyData.Lev=r.FormValue("lev")
	}

	if len(r.Form) == 0 {
		jsn, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logs.Debug("Error reading the body", err)
		}
		err = json.Unmarshal(jsn, &VerifyData)
	}
	recv, err:= json.Marshal(VerifyInfo{
		Sig:VerifyData.Sig,
		Msg:VerifyData.Msg,
		Lev:VerifyData.Lev,
		Pub:VerifyData.Pub,
	})
	logs.Info("Received verify request data: %v\n", string(recv))

	//检查签名是否在数据库
	//2.验证pub
	if len(VerifyData.Pub)!=132{
		res, _:= json.Marshal(Ret{
			Error:"1",
			Msg:"公钥格式错误",
		})
		w.Write(res)
		return
	}

	//判断level是否合法
	level,err :=  strconv.Atoi(VerifyData.Lev)
	if level>3 && level<1  {
		res, _:= json.Marshal(Ret{
			Error:"2",
			Msg:"第三方认证的level等级错误",
		})
		w.Write(res)
		return
	}

	_,err= hexutil.Decode(VerifyData.Pub)
	if err!=nil{
		res, _:= json.Marshal(Ret{
			Error:"1",
			Msg:"公钥格式错误",
		})
		w.Write(res)
		return
	}

	_,err=model.GetUserSigByName(VerifyData.Sig)
	if err !=nil {
		fmt.Println(err)
		logs.Error(err)
		return
	}

	//if sig != nil {
	//	res, _:= json.Marshal(Ret{
	//		Error:"2",
	//		Msg:"您的第三方信息已经通过验证，请您不要重复验证",
	//	})
	//	w.Write(res)
	//	return
	//}

	//验证第三方签名
	//if PubData.Sig==true {

	//}

	//如果三方签名验证通过，存储数据库
	verifyInfo := &model.VerifyInfo{}
	verifyInfo.Pub = VerifyData.Pub
	verifyInfo.Sig = VerifyData.Sig
	verifyInfo.Lev,_ = strconv.Atoi(VerifyData.Lev)
	err = model.CreateVerifyInfo(verifyInfo)
	if err != nil {
		logs.Warn("invalid parameter")
	}
	res, err:= json.Marshal(Ret{
		Error:"0",
		Msg:"您的第三方签名已通过验证",
	})
	if err !=nil {
		fmt.Println(err)
	}
	w.Write(res)
}



