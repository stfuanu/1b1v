package core

import (
    // "crypto/ecdsa"
    // "crypto/rand"
    // "crypto/elliptic"
    // "crypto/sha256"
    "encoding/hex"
    "fmt"
    "log"
    "github.com/mr-tron/base58"
    // "math/big"

)

func base58Encode(input []byte) []byte {
    encode := base58.Encode(input)

    return []byte(encode)
}

func base58Decode(input []byte) []byte {
    decode, err := base58.Decode(string(input[:]))
    if err != nil {
        log.Panic(err)
    }
    return decode
}

func HexDecodeString(encoded string) string {
    // const s = encoded
    decoded, err := hex.DecodeString(encoded)
    if err != nil {
        log.Fatal(err)
    }

    return fmt.Sprintf("%s",decoded)

}

func HexDecode(encoded string) []byte {
    src := []byte(encoded)

    dst := make([]byte, hex.DecodedLen(len(src)))
    n, err := hex.Decode(dst, src)
    if err != nil {
        log.Fatal(err)
    }

    return dst[:n]

}