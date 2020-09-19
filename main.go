package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
)

func main() {
	publicKeyFileName := flag.String("publicKey", "", "public key filename")
	fileName := flag.String("file", "", "file to verify")
	signatureFileName := flag.String("sign", "", "signature file name")
	flag.Parse()

	if *publicKeyFileName == "" || *fileName == "" || *signatureFileName == "" {
		log.Println("Some flags are empty")
		return
	}

	msg, err := ioutil.ReadFile(*fileName)
	if err != nil {
		log.Println(err)
		return
	}

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)

	signature, err := ioutil.ReadFile(*signatureFileName)
	if err != nil {
		log.Println(err)
		return
	}

	publicKey, err := ioutil.ReadFile(*publicKeyFileName)
	if err != nil {
		log.Println(err)
		return
	}
	key, err := x509.ParsePKIXPublicKey(publicKey)
	rsakey := key.(*rsa.PublicKey)
	if err != nil {
		log.Println(err)
		return
	}
	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	err = rsa.VerifyPSS(rsakey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		log.Println("could not verify signature: ", err)
		return
	}
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	log.Println("signature verified")
}
