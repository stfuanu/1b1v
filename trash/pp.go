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
// var curve := elliptic.P256()
//GeneratePrivateKey : ecdsa.PrivateKey
func GeneratePrivateKey() (*big.Int, error) {
    var privateKey *ecdsa.PrivateKey
    var privateKeyGenerationError error
    privateKey, privateKeyGenerationError = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if privateKeyGenerationError != nil {
        return privateKey.D, privateKeyGenerationError
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
    n := new(big.Int)
    n, _ = n.SetString("95475427764091888964603543137677641743922088103258025093701944505948996222151", 10)


    // pvtkey , _ := GeneratePrivateKey()
    pubkey := GeneratePublicKey(n)

    fmt.Println(n,pubkey)


}

// //Signature :
// type Signature struct {
//     R *big.Int
//     S *big.Int
// }

// //SignMessage : Generates a valid digital signature for golang's ecdsa library
// func SignMessage(message string, privateKey *big.Int) (Signature, error) {
//     var result Signature
//     msgHash := fmt.Sprintf(
//         "%x",
//         sha256.Sum256([]byte(message)),
//     )
//     privateKeyStruct, privateKeyGenerationError := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//     if privateKeyGenerationError != nil {
//         return result, privateKeyGenerationError
//     }

//     privateKeyStruct.D = privateKey

//     signatureR, signatureS, signatureGenerationError := ecdsa.Sign(rand.Reader, privateKeyStruct, []byte(msgHash))
//     if signatureGenerationError != nil {
//         return result, signatureGenerationError
//     }
//     result.R = signatureR
//     result.S = signatureS
//     return result, nil
// }

// //SignExternalMessage : Generates a valid digital signature for javascript's elliptic library https://github.com/indutny/elliptic
// func SignExternalMessage(message string, privateKey *big.Int) (Signature, error) {
//     var result Signature
//     msgHash := fmt.Sprintf(
//         "%x",
//         sha256.Sum256([]byte(message)),
//     )
//     privateKeyStruct, privateKeyGenerationError := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//     if privateKeyGenerationError != nil {
//         return result, privateKeyGenerationError
//     }

//     privateKeyStruct.D = privateKey
//     hash, hashDecodeError := hex.DecodeString(msgHash)

//     if hashDecodeError != nil {
//         return result, hashDecodeError
//     }

//     signatureR, signatureS, signatureGenerationError := ecdsa.Sign(rand.Reader, privateKeyStruct, hash)
//     if signatureGenerationError != nil {
//         return result, signatureGenerationError
//     }
//     result.R = signatureR
//     result.S = signatureS
//     return result, nil
// }

// //VerifyMessage : Verifies signatures generated using golang's ecdsa function
// func VerifyMessage(message string, publicKey *ecdsa.PublicKey, signature Signature) (bool, error) {
//     msgHash := fmt.Sprintf(
//         "%x",
//         sha256.Sum256([]byte(message)),
//     )
//     return ecdsa.Verify(publicKey, []byte(msgHash), signature.R, signature.S), nil
// }

// //VerifyExternalMessage : Verifies signatures generated using the javascript elliptic library
// // https://github.com/indutny/elliptic
// func VerifyExternalMessage(message string, publicKey *ecdsa.PublicKey, signature Signature) (bool, error) {
//     msgHash := fmt.Sprintf(
//         "%x",
//         sha256.Sum256([]byte(message)),
//     )
//     hash, hashDecodeError := hex.DecodeString(msgHash)

//     if hashDecodeError != nil {
//         return false, hashDecodeError
//     }
//     return ecdsa.Verify(publicKey, hash, signature.R, signature.S), nil
// }