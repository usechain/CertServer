//@Time  : 2018/3/13 13:46
//@Author: Greg Li
package main

import (
	"cert_service/server/generateCA"
)

func main(){
	generateCA.GenRCA("292409083@qq.com",true,"P521","rca.crt","rca.key","rca.pem")
	generateCA.GenECA("",true,"P521","eca.crt","eca.key","eca.pem")
	generateCA.GenTCA("0xd2a132139ca63447a7affc49143c17bf81948d54@163.com",true,"P521","tca.crt","tca.key","tca.pem")
	//generateCA.GenTXTCA("0xd2a132139ca63447a7affc49143c17bf81948d54@163.com",true,"P521","tcert.crt","tcert.key","tcert.pem")
	//generateCA.GenEcert(true,"P521","eCert.crt",pub)
}
