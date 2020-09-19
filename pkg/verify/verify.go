package verify

import (
	"crypto"
	"crypto/rsa"
	"log"
)

func Verify(rsakey *rsa.PublicKey, msgHashSum []byte, signature []byte) bool {
	err := rsa.VerifyPSS(rsakey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		log.Println("could not verify signature: ", err)
		return false
	}
	return true
}
