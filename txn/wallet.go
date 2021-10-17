package main

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/elliptic"
    // "crypto/sha256"
    // "encoding/hex"
    "fmt"
    "math/big"

    // "github.com/elliptic"
)
// var curve = elliptic.P256()
//GeneratePrivateKey : ecdsa.PrivateKey
func GeneratePrivateKey() (*big.Int, error) {
    // var privateKey *ecdsa.PrivateKey
    // var err error
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return privateKey.D, err
    }
    return privateKey.D, nil
}

//GeneratePublicKey :
func GeneratePublicKey(privateKey *big.Int) ecdsa.PublicKey {
    var pri ecdsa.PrivateKey
    pri.D, _ = new(big.Int).SetString(fmt.Sprintf("%x", privateKey), 16)
    pri.PublicKey.Curve = elliptic.P256()
    pri.PublicKey.X, pri.PublicKey.Y = pri.PublicKey.Curve.ScalarBaseMult(pri.D.Bytes())

    publicKey := ecdsa.PublicKey{
        Curve: elliptic.P256(),
        X:     pri.PublicKey.X,
        Y:     pri.PublicKey.Y,
    }

    return publicKey
}



func main() {
// idhar se  :==== https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
// The private key is generated as a random integer in the range [0...n-1]. 
// The public key pubKey is a point on the elliptic curve, 
// calculated by the EC point multiplication: 
// pubKey = privKey * G (the private key, multiplied by the generator point G).


    // pvtkey, _ := new(big.Int).SetString("67741572849049704287421412783482178807814011625242462052090743819077275772091", 10)
    pvtkey , _ := GeneratePrivateKey()
    publicStruct := GeneratePublicKey(pvtkey)
    pubkey := append(publicStruct.X.Bytes(), publicStruct.Y.Bytes()...)


    fmt.Println(fmt.Sprintf("%d , %x",pvtkey,pubkey))
}

func GetRandom256() *big.Int {
    //Max random value, a 130-bits integer, i.e 2^130 - 1
    max := new(big.Int)
    max.Exp(big.NewInt(2), big.NewInt(256), nil).Sub(max, big.NewInt(1))

    //Generate cryptographically strong pseudo-random between 0 - max
    n, err := rand.Int(rand.Reader, max)
    if err != nil {
        //error handling
    }
    // fmt.Println("1-11 : " ,n,max)

    //String representation of n in base 32
    return n

}