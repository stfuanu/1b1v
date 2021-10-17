// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"crypto/sha256"
	"fmt"
	"math/big"
)




func main() {
	// privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
		// panic(err)
	// }

	PVT := new(ecdsa.PrivateKey)

	// var PVT ecdsa.PrivateKey

	pvtkey := "10812451649439301607584803068021549971624436680647291754013889458278037268332"
	hextoint ,_ := new(big.Int).SetString(pvtkey,16)
	PVT.D = hextoint
	PVT.PublicKey = GeneratePublicKey(hextoint)

	msg := "hello,world"
	hash := sha256.Sum256([]byte(msg))
	fmt.Println("Hash is : ", hex.EncodeToString(hash[:]))

	r ,sig, err := ecdsa.Sign(rand.Reader, PVT, hash[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %x %d\n", sig , r)

	valid := ecdsa.Verify(&PVT.PublicKey, hash[:], r, sig)
	fmt.Println("signature verified:", valid)
}

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