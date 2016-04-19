
package main

import (
        "os"
	"fmt"
	"time"
	"math/big"
	"io/ioutil"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
  "encoding/gob"
  "encoding/pem"
  "crypto/x509/pkix"
 )

 func main() {
     // ok, lets populate the certificate with some data
     // not all fields in Certificate will be populated
     // see Certificate structure at
     // http://golang.org/pkg/crypto/x509/#Certificate
     template := &x509.Certificate {
              IsCA : true,
              BasicConstraintsValid : true,
              SubjectKeyId : []byte{1,2,3},
              SerialNumber : big.NewInt(1234),
              Subject : pkix.Name{
                        Country : []string{"Earth"},
                        Organization: []string{"Mother Nature"},
              },
              NotBefore : time.Now(),
              NotAfter : time.Now().AddDate(5,5,5),
              // see http://golang.org/pkg/crypto/x509/#KeyUsage
              ExtKeyUsage : []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
              KeyUsage : x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
     }

     // generate private key
     privatekey, err := rsa.GenerateKey(rand.Reader, 4096)
     if err != nil {
       fmt.Println(err)
     }

     publickey := &privatekey.PublicKey
     // create a self-signed certificate. template = parent
     var parent = template
     cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey,privatekey)
     if err != nil {
        fmt.Println(err)
     }
//         fmt.Println(string(cert))

     // save private key
     pkey := x509.MarshalPKCS1PrivateKey(privatekey)
     ioutil.WriteFile("private.key", pkey, 0777)
     fmt.Println("private key saved to private.key")

     // save public key
     pubkey, _ := x509.MarshalPKIXPublicKey(publickey)
     ioutil.WriteFile("public.key", pubkey, 0777)
     fmt.Println("public key saved to public.key")

     // save cert
     ioutil.WriteFile("cert.pem", cert, 0777)
     fmt.Println("certificate saved to cert.pem")


     // these are the files save with encoding/gob style
     privkeyfile, _ := os.Create("privategob.key")
     privkeyencoder := gob.NewEncoder(privkeyfile)
     privkeyencoder.Encode(privatekey)
     privkeyfile.Close()

     pubkeyfile, _ := os.Create("publickgob.key")
     pubkeyencoder := gob.NewEncoder(pubkeyfile)
     pubkeyencoder.Encode(publickey)
     pubkeyfile.Close()

     // this will create plain text PEM file.
     pemfile, _ := os.Create("private.pem")
     var pemkey = &pem.Block{
                  Type : "RSA PRIVATE KEY",
                  Bytes : x509.MarshalPKCS1PrivateKey(privatekey)}
     pem.Encode(pemfile, pemkey)
     pemfile.Close()

 }
