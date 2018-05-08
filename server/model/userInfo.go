//@Time  : 2018/3/15 11:48
//@Author: Greg Li
package model

import (
	"github.com/astaxie/beego/logs"
	"github.com/jmoiron/sqlx"
	"fmt"
)

type VerifyInfo struct {
	PubId	int    `db:"pub_id"`
	Pub		string `db:"pub"`
	Sig 	string `db:"sig"`
	Lev		int 	`db:"lev"`
}

type UserInfo struct {
	UserId	int    `db:"user_id"`
	Addr	string `db:"addr"`
	Tcert	string `db:"tcert_name"`
	Pub 	string `db:"pub"`
	MainAddrTag int `db:"tag"`
}

var (
	Db *sqlx.DB
)

func InitDb(db *sqlx.DB) {
	Db = db
}

func GetAllUserInfo() (userList []UserInfo, err error) {

	err = Db.Select(&userList, "select user_id,addr,tcert_name,pub from userInfo")
	if err != nil {
		logs.Warn("Get All User Info failed, err:%v", err)
		return
	}
	return
}
func GetUserSigByName(sigClient string) (sigDB []string, err error) {

	err = Db.Select(&sigDB, "select sig from VerifyInfo where sig=?", sigClient)
	if err != nil {
		logs.Warn("select sig failed, Db.Exec error:%v", err)
		return
	}
	return
}

func GetUserPubByPub(pubClient string) (pubDB []string, err error) {
	
	err = Db.Select(&pubDB, "select pub from VerifyInfo where pub=?", pubClient)
	if err != nil {
		logs.Warn("select pub failed, Db.Exec error:%v", err)
		return
	}
	return
}

func GetUserLevByPub(pubClient string) (lev []int, err error) {

	err = Db.Select(&lev, "select lev from VerifyInfo where pub=?", pubClient)
	if err != nil {
		logs.Warn("select lev failed, Db.Exec error:%v", err)
		return
	}
	return
}

func GetUserAddrByAddr(addr string) (pubDB []string, err error) {

	err = Db.Select(&pubDB, "select addr from userInfo where addr=?", addr)
	if err != nil {
		logs.Warn("select pub failed, Db.Exec error:%v", err)
		return
	}
	return
}

func CreateVerifyInfo(info *VerifyInfo) (err error) {

	conn, err := Db.Begin()
	if err != nil {
		logs.Warn("CreateUser failed, Db.Begin error:%v", err)
		return
	}

	defer func() {
		if err != nil {
			conn.Rollback()
			return
		}
		conn.Commit()
	}()
	_, err = conn.Exec("insert into VerifyInfo(pub_id,pub,sig,lev)values(?,?,?,?)",
		info.PubId, info.Pub,info.Sig,info.Lev)

	if err != nil {
		logs.Warn("CreateUser failed, Db.Exec error:%v", err)
		return
	}
	return
}

func CreateUserInfo(info *UserInfo) (err error) {

	conn, err := Db.Begin()
	if err != nil {
		logs.Warn("CreateUser failed, Db.Begin error:%v", err)
		return
	}

	defer func() {
		if err != nil {
			conn.Rollback()
			return
		}
		conn.Commit()
	}()
	_, err = conn.Exec("insert into userInfo(user_id,addr,tcert_name,pub,tag)values(?, ?, ?,?,?)",
		info.UserId, info.Addr, info.Tcert,info.Pub,info.MainAddrTag)

	if err != nil {
		logs.Warn("CreateUser failed, Db.Exec error:%v", err)
		return
	}
	return
}

func UpdateUserInfo(info *UserInfo) (err error) {
	_, err = Db.Exec("update userinfo set tag=?,pub=? where addr=?", info.MainAddrTag, info.Pub,info.Addr)
	if err != nil {
		fmt.Println("exec failed, ", err)
		return
	}
	return
}

func QueryPubNum(pubClient string) (int)  {
	rows, err :=Db.Query("select count(*) from userinfo where pub=?",pubClient)
	defer rows.Close()
	rows.Next()
	var count int
	err = rows.Scan(&count)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("count: %d\n", count)
	return count
}


/*
CREATE DATABASE certserver DEFAULT CHARSET utf8 COLLATE utf8_general_ci;

create table VerifyInfo(
	pub_id int auto_increment primary key,
	sig varchar(1024) not null,
	pub varchar(1024) not null,
	lev int
)ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

create table userInfo(
	user_id int auto_increment primary key,
	addr varchar(1024) not null,
	tcert_name varchar(1024) not null,
	pub varchar(1024) not null,
	tag int not null
)ENGINE=InnoDB DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
*/
