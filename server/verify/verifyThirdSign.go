//@Time  : 2018/3/9 14:16
//@Author: Greg Li
package verify

import (
	"fmt"
)


func main1() {

	publicKeyFilename := "tca.pem"
	signatureFilename := "sig.txt"
	messageFilename   := "addr.txt"

	publicKey := loadPublicKeyFromPemFile(publicKeyFilename)
	signature := loadFile(signatureFilename)
	message := loadFile(messageFilename)

	valid := verifyRsaSig(signature, message, publicKey)

	if valid {
		fmt.Println("Signature verified.")
	} else {
		fmt.Println("Signature could not be verified.")
	}
}
