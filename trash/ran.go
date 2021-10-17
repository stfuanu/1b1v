package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func main() {
	//Max random value, a 130-bits integer, i.e 2^130 - 1
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(256), nil).Sub(max, big.NewInt(1))

	//Generate cryptographically strong pseudo-random between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		//error handling
	}
	fmt.Println("1-11 : " ,n,max)

	//String representation of n in base 32
	nonce := n.String()

	fmt.Println(nonce)
}
