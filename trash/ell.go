package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "log"
    "fmt"
    "encoding/hex"
    "math/big"

    "golang.org/x/crypto/ripemd160"
    "github.com/mr-tron/base58"
)

const (
    checksumLength = 4
    //hexadecimal representation of 0
    version = byte(0x00)
)

//wallet.go
type Wallet struct {
    //ecdsa = eliptical curve digital signiture algorithm
    PrivateKey ecdsa.PrivateKey
    PublicKey  []byte
}

func NewKeyPair() (ecdsa.PrivateKey, []byte) {
    curve := elliptic.P256()

    private, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        log.Panic(err)
    }

    fmt.Println(private.Public())

    // fmt.Println(private)

    curveParams := curve.Params()

    pub := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
    fmt.Println(fmt.Sprintf("CurveName : %s \nBitsize : %d \nGx : %v \nGy : %v ",curveParams.Name , curveParams.BitSize , curveParams.Gx,curveParams.Gy))
    

    fmt.Println(fmt.Sprintf("\n(X,Y) : %t : (%v,%v) ", curve.IsOnCurve(private.PublicKey.X, private.PublicKey.Y) , private.PublicKey.X , private.PublicKey.Y ))
    // fmt.Println()
    fmt.Println(fmt.Sprintf("x:%v \ny:%v \nappend(x,y):%v", private.PublicKey.X.Bytes() , private.PublicKey.Y.Bytes() , pub[:]))

    return *private, pub
}

func PublicKeyHash(publicKey []byte) []byte {
    hashedPublicKey := sha256.Sum256(publicKey)

    hasher := ripemd160.New()
    _, err := hasher.Write(hashedPublicKey[:])
    if err != nil {
        log.Panic(err)
    }
    publicRipeMd := hasher.Sum(nil)
    fmt.Println("\nhashedPublicKey sha256(publicKey) : ", hex.EncodeToString(hashedPublicKey[:]))
    fmt.Println("publicRipeMd rice160(hashedPublicKey) : ", hex.EncodeToString(publicRipeMd[:]))

    return publicRipeMd
}


// func ExampleDecodeString() {
//     const s = "1ce297c16603a4ee22bd11f87576af5452559b84063f544f4067c135d772b9e6"
//     decoded, err := hex.DecodeString(s)
//     if err != nil {
//         log.Fatal(err)
//     }

//     fmt.Printf("%s\n", decoded)

//     // Output:
//     // Hello Gopher!
// }


func main() {

// pvt , pub := NewKeyPair()

// fmt.Println(PublicKeyHash(pub))
// fmt.Println(pvt)
    // MakeWallet()
    wallet := MakeWallet()
    address := fmt.Sprintf("\nAddress : %s \nPubKey : %x \nPvtKey : %x::%d::%s", wallet.Address() , wallet.PublicKey , wallet.PrivateKey.D  , wallet.PrivateKey.D , base58Encode([]byte(wallet.PrivateKey.D.String())) )
    

    encopub := fmt.Sprintf("%x",wallet.PublicKey)
    fmt.Println(fmt.Sprintf("\nbytepub : %v  \nhexpub : %v \n", encopub , HexDecode(encopub)) )

    inttohex := fmt.Sprintf("%x",wallet.PrivateKey.D)
    hextoint,_ := new(big.Int).SetString(inttohex,16)

    fmt.Printf("%d --> %s --> %d \n",wallet.PrivateKey.D , inttohex , hextoint )

    encopvt := base58Encode([]byte(wallet.PrivateKey.D.String()))
    fmt.Println(fmt.Sprintf("PVT.D : %s \nHex(pvt) : %x \nBase58(pvt) : %s", string(base58Decode(encopvt)) , wallet.PrivateKey.D , encopvt ))



    // fmt.Println(hextoint)
    fmt.Println(address)


}

func HexDecodeString(encoded string) string {
    // const s = encoded
    decoded, err := hex.DecodeString(encoded)
    if err != nil {
        log.Fatal(err)
    }

    return fmt.Sprintf("%s",decoded)

    // Output:
    // Hello Gopher!
}

func HexDecode(encoded string) []byte {
    src := []byte(encoded)

    dst := make([]byte, hex.DecodedLen(len(src)))
    n, err := hex.Decode(dst, src)
    if err != nil {
        log.Fatal(err)
    }

    return dst[:n]

    // Output:
    // Hello Gopher!
}



func MakeWallet() *Wallet {
    privateKey, publicKey := NewKeyPair()
    wallet := Wallet{privateKey, publicKey}
    return &wallet
}

func (w *Wallet) Address() []byte {
    // Step 1/2
    pubHash := PublicKeyHash(w.PublicKey)
    fmt.Println("pubHash : ", hex.EncodeToString(pubHash[:]))
    //Step 3
    versionedHash := append([]byte{version}, pubHash...)
    fmt.Println("versionedHash byte(0x00) : ", hex.EncodeToString(versionedHash[:]))
    //Step 4
    checksum := Checksum(versionedHash)
    fmt.Println("checksum sha256(sha256(versionedHash)) ", hex.EncodeToString(checksum[:]))
    //Step 5
    finalHash := append(versionedHash, checksum...)
    fmt.Println("finalHash : ", hex.EncodeToString(finalHash[:]))
    // fmt.Println(finalHash)
    //Step 6
    address := base58Encode(finalHash)
    fmt.Println("Wallet Address : base58Encode(finalHash) : ", string(address[:]))
    return address
}


//wallet.go
func Checksum(ripeMdHash []byte) []byte {
    firstHash := sha256.Sum256(ripeMdHash)
    secondHash := sha256.Sum256(firstHash[:])

    return secondHash[:checksumLength]
}

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
