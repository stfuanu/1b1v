package core

import "fmt"

// import (
//     "crypto/ecdsa"
//     "crypto/elliptic"
//     "crypto/rand"
//     "crypto/sha256"
//     "log"

//     "golang.org/x/crypto/ripemd160"
// )

// const (
//     checksumLength = 4
//     //hexadecimal representation of 0
//     version = byte(0x00)
// )

// //wallet.go
// type Wallet struct {
//     //ecdsa = eliptical curve digital signiture algorithm
//     PrivateKey ecdsa.PrivateKey
//     PublicKey  []byte
// }

// func NewKeyPair() (ecdsa.PrivateKey, []byte) {
//     curve := elliptic.P256()

//     private, err := ecdsa.GenerateKey(curve, rand.Reader)
//     if err != nil {
//         log.Panic(err)
//     }

//     pub := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

//     return *private, pub
// }

func Top() {
    fmt.Println("INSIDE ")
}

// func PublicKeyHash(publicKey []byte) []byte {
//     hashedPublicKey := sha256.Sum256(publicKey)

//     hasher := ripemd160.New()
//     _, err := hasher.Write(hashedPublicKey[:])
//     if err != nil {
//         log.Panic(err)
//     }
//     publicRipeMd := hasher.Sum(nil)

//     return publicRipeMd
// }