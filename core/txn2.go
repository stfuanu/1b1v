package core

import (
//     "crypto/ecdsa"
//     "crypto/rand"
//     "crypto/elliptic"
//     "crypto/sha256"
//     "encoding/hex"
    "fmt"
//     "log"
//     "math/big"

//     "golang.org/x/crypto/ripemd160"
//     "github.com/mr-tron/base58"

)

func to(){
	fmt.Println("he")
}

// can later add multiple []input/output (not needed in case of votes ig)
// type Vote struct {
// 	TXID		string	`json:"txhash"`
// 	Voter 		string	`json:"voter"`
// 	Candidate 	string	`json:"candidate"`
// 	Value 		int		`json:"value"`
// }

// Considering that transactions unlock previous outputs, 
// redistribute their values, and lock new outputs, 

// type TXInput struct {
// 	Txid      []byte
// 	Vout      int
// 	Signature []byte
// 	PubKey    []byte
// }

// type TXOutput struct {
// 	Value      int
// 	PubKeyHash []byte
// }