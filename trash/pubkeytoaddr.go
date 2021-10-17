package main

import (
    // "crypto/ecdsa"
    // "crypto/rand"
    // "crypto/elliptic"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    // "bytes"
    "log"
    // "math/big"

    "golang.org/x/crypto/ripemd160"
    "github.com/mr-tron/base58"

    // "github.com/elliptic"
)
// 

const (
    checksumLength = 4
    //hexadecimal representation of 0
    version = byte(0x00)
)




func main() {

    pubkey := "304402202eab8b05f4d88d156d2f629a782d4c7a0b2ce863a7995603a4bbef0748b0127b02201349608e99cd0eaca0ba85a0eb637b8ec75572dcf123396afd335408f5bbb0f401"


    fmt.Printf("%s",Address(pubkey))


}



func Address(pubkey string) []byte {

    // npub,_ := new(big.Int).SetString(pubkey,16)
    npub, _ := hex.DecodeString(pubkey)
    // Step 1/2
    pubHash := PublicKeyHash(npub)
    // fmt.Println("pubHash : ", hex.EncodeToString(pubHash[:]))
    //Step 3
    versionedHash := append([]byte{version}, pubHash...)
    // fmt.Println("versionedHash byte(0x00) : ", hex.EncodeToString(versionedHash[:]))
    //Step 4
    checksum := Checksum(versionedHash)
    // fmt.Println("checksum sha256(sha256(versionedHash)) ", hex.EncodeToString(checksum[:]))
    //Step 5
    finalHash := append(versionedHash, checksum...)
    // fmt.Println("finalHash : ", hex.EncodeToString(finalHash[:]))
    // fmt.Println(finalHash)
    //Step 6
    address := base58Encode(finalHash)
    // fmt.Println("Wallet Address : base58Encode(finalHash) : ", string(address[:]))
    return address
}

func base58Encode(input []byte) []byte {
    encode := base58.Encode(input)

    return []byte(encode)
}

func PublicKeyHash(publicKey []byte) []byte {
    hashedPublicKey := sha256.Sum256(publicKey)

    hasher := ripemd160.New()
    _, err := hasher.Write(hashedPublicKey[:])
    if err != nil {
        log.Panic(err)
    }
    publicRipeMd := hasher.Sum(nil)
    // fmt.Println("\nhashedPublicKey sha256(publicKey) : ", hex.EncodeToString(hashedPublicKey[:]))
    // fmt.Println("publicRipeMd rice160(hashedPublicKey) : ", hex.EncodeToString(publicRipeMd[:]))

    return publicRipeMd
}

func Checksum(ripeMdHash []byte) []byte {
    firstHash := sha256.Sum256(ripeMdHash)
    secondHash := sha256.Sum256(firstHash[:])

    return secondHash[:checksumLength]
}

