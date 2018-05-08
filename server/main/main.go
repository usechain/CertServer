//@Time  : 2018/3/15 16:59
//@Author: Greg Li
package main

import (
	"net/http"
	"cert_service/server/model"
	"github.com/jmoiron/sqlx"
	_ "github.com/go-sql-driver/mysql"
	"github.com/astaxie/beego/logs"
	"cert_service/server/handlers"
	_ "net/http/pprof"
	"fmt"
)

func initDb() (err error) {

	database, err := sqlx.Open("mysql", "root:********@tcp(127.0.0.1:3306)/certserver")
	if err != nil {
		logs.Debug("open mysql failed,", err)
		return
	}
	model.InitDb(database)
	return
}

func main() {
	//初始化配置文件
	filename := "./conf/log.conf"
	err := loadConf("ini", filename)
	if err != nil {
		fmt.Printf("load conf failed, err:%v\n", err)
		panic("load conf failed")
		return
	}

	//初始化日志
	err = initLogger()
	if err != nil {
		fmt.Printf("load logger failed, err:%v\n", err)
		panic("load logger failed")
		return
	}
	logs.Debug("load conf succ, config:%v", appConfig)
	err = initDb()
	if err != nil {
		logs.Warn("initDb failed, err:%v", err)
		return
	}
	server:=http.Server{
		Addr:"10.30.47.7:8888",
	}
	http.HandleFunc("/verify",handlers.VerifyHandler)
	http.HandleFunc("/tcert", handlers.TcertHandler)
	err = server.ListenAndServe()
	logs.Error(err)
}