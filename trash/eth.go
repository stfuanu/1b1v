package main

import (
    "crypto/ecdsa"
    "fmt"
    "github.com/ethereum/go-ethereum/common/hexutil"
    "github.com/ethereum/go-ethereum/crypto"
    "golang.org/x/crypto/sha3"
)

func main() {
    privateKey,_ := crypto.GenerateKey()

    privateKeyBytes := crypto.FromECDSA(privateKey)
    fmt.Printf("Private key: %s\n",hexutil.Encode(privateKeyBytes)[2:]) 

    publicKey := privateKey.Public()
    publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)


    publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
    fmt.Printf("Public key:\t %s\n",hexutil.Encode(publicKeyBytes)[4:]) 

    address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
    fmt.Printf("Public address (from ECDSA): \t%s\n",address) 

    hash := sha3.NewLegacyKeccak256()
    hash.Write(publicKeyBytes[1:])
    fmt.Printf("Public address (Hash of public key):\t%s\n",hexutil.Encode(hash.Sum(nil)[12:])) 
}