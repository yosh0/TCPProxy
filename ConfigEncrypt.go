package main

import (
	"os"
	"fmt"
	"log"
	"hash"
	"io/ioutil"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
)

func main() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	data := make([]byte, 1000)
	count, err := file.Read(data)
	if err != nil {
		log.Fatal(err)
	}
        fmt.Println(count)
	message := data[:count]

    	private_key, err := os.Open("privategob.key")
   	if err != nil {
     		fmt.Println(err)
     		os.Exit(1)
   	}
   	decoder := gob.NewDecoder(private_key)
   	var privatekey *rsa.PrivateKey
   	err = decoder.Decode(&privatekey)

   	if err != nil {
      		fmt.Println(err.Error())
      		os.Exit(1)
   	}
   	fmt.Printf("Private Key : \n%x\n", privatekey)

    	public_key, err := os.Open("publickgob.key")
   	if err != nil {
     		fmt.Println(err)
     		os.Exit(1)
   	}
   	decoder = gob.NewDecoder(public_key)
   	var publickey *rsa.PublicKey
   	err = decoder.Decode(&publickey)

	if err != nil {
      		fmt.Println(err)
      		os.Exit(1)
   	}
   	fmt.Printf("Public key : \n%x\n", publickey)

    	encrypted := encrypt_oaep(publickey, message, []byte("123"))
    	fmt.Println("ENCRYPTED")
    	fmt.Println(string(encrypted))

    	ioutil.WriteFile("config_cr.json", encrypted, 0777)

}

func encrypt_oaep(public_key *rsa.PublicKey, plain_text, label []byte) (encrypted []byte) {
    var err error
    var md5_hash hash.Hash

    md5_hash = md5.New()

    if encrypted, err = rsa.EncryptOAEP(md5_hash, rand.Reader, public_key, plain_text, label); err != nil {
        log.Fatal(err)
    }
    return
}
