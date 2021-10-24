package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	// "encoding/hex"
	"bytes"
	"fmt"
	"log"
	"math/big"
	"regexp"

	"golang.org/x/crypto/ripemd160"
	// "github.com/mr-tron/base58"
	// "github.com/elliptic"
)

// var curve = elliptic.P256()
//GeneratePrivateKey : ecdsa.PrivateKey

const (
	checksumLength = 4
	//hexadecimal representation of 0
	version = byte(0x00)
)

//wallet.go

// type Wallets struct {
//     Wallets map[string]*Wallet
// }

type Wallet struct {
	//ecdsa = eliptical curve digital signiture algorithm
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

func MakeWallet() *Wallet {
	privateKey, publicKey := NewKeyPair()
	wallet := Wallet{privateKey, publicKey}
	return &wallet
}

func New() {
	w := MakeWallet()
	// w.PrivateKey.D , _ := new(big.Int).SetString("67741572849049704287421412783482178807814011625242462052090743819077275772091", 10)
	// publicStruct := GeneratePublicKey(pvtkey)
	// w.PrivateKey := GeneratePrivateKey()
	// publicStruct := GeneratePublicKey(pvtkey)
	// w.PublicKey := append(publicStruct.X.Bytes(), publicStruct.Y.Bytes()...)
	fmt.Printf("%x , %d , %s \n", w.PublicKey, w.PrivateKey.D, w.Address())
	fmt.Println(ValidateAddress(fmt.Sprintf("%s", w.Address())))

}

// New()

func (w *Wallet) Address() []byte {
	// Step 1/2
	pubHash := PublicKeyHash(w.PublicKey)
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

// func ReverseBytes(data []byte) {
//     for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
//         data[i], data[j] = data[j], data[i]
//     }
// }

// // Base58Encode encodes a byte array to Base58
// func Base58Encodee(input []byte) []byte {
//     var result []byte

//     x := big.NewInt(0).SetBytes(input)

//     base := big.NewInt(int64(len(b58Alphabet)))
//     zero := big.NewInt(0)
//     mod := &big.Int{}

//     for x.Cmp(zero) != 0 {
//         x.DivMod(x, base, mod)
//         result = append(result, b58Alphabet[mod.Int64()])
//     }

//     // https://en.bitcoin.it/wiki/Base58Check_encoding#Version_bytes
//     if input[0] == 0x00 {
//         result = append(result, b58Alphabet[0])
//     }

//     ReverseBytes(result)

//     return result
// }

// var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// func Base58Decodee(input []byte) []byte {
//     result := big.NewInt(0)

//     for _, b := range input {
//         charIndex := bytes.IndexByte(b58Alphabet, b)
//         result.Mul(result, big.NewInt(58))
//         result.Add(result, big.NewInt(int64(charIndex)))
//     }

//     decoded := result.Bytes()

//     if input[0] == b58Alphabet[0] {
//         decoded = append([]byte{0x00}, decoded...)
//     }

//     return decoded
// }

// ValidateAddress check if address if valid
func ValidateAddress(address string) bool {
	matched, _ := regexp.MatchString(`^1[a-zA-Z0-9.]{30,40}`, address)
	// smartMatch, _ := regexp.MatchString(`SMART_CONTRACT`, address)

	// if smartMatch {
	// 	return true
	// }

	if !matched {
		// fmt.Println("not regex match",address)
		return false
	}

	pubKeyHash := base58Decode([]byte(address))
	actualChecksum := pubKeyHash[len(pubKeyHash)-checksumLength:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-checksumLength]
	targetChecksum := Checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Compare(actualChecksum, targetChecksum) == 0
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

func NewKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()

	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}

	// fmt.Println(private.Public())

	// fmt.Println(private)

	// curveParams := curve.Params()

	pub := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
	// fmt.Println(fmt.Sprintf("CurveName : %s \nBitsize : %d \nGx : %v \nGy : %v ",curveParams.Name , curveParams.BitSize , curveParams.Gx,curveParams.Gy))

	// fmt.Println(fmt.Sprintf("\n(X,Y) : %t : (%v,%v) ", curve.IsOnCurve(private.PublicKey.X, private.PublicKey.Y) , private.PublicKey.X , private.PublicKey.Y ))
	// // fmt.Println()
	// fmt.Println(fmt.Sprintf("x:%v \ny:%v \nappend(x,y):%v", private.PublicKey.X.Bytes() , private.PublicKey.Y.Bytes() , pub[:]))

	return *private, pub
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

//wallet.go
func Checksum(ripeMdHash []byte) []byte {
	firstHash := sha256.Sum256(ripeMdHash)
	secondHash := sha256.Sum256(firstHash[:])

	return secondHash[:checksumLength]
}

// func main() {
//     New()
// }
// ----------------------------
// // idhar se  :==== https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
// // The private key is generated as a random integer in the range [0...n-1].
// // The public key pubKey is a point on the elliptic curve,
// // calculated by the EC point multiplication:
// // pubKey = privKey * G (the private key, multiplied by the generator point G).

//     // pvtkey, _ := new(big.Int).SetString("67741572849049704287421412783482178807814011625242462052090743819077275772091", 10)
//     pvtkey , _ := GeneratePrivateKey()
//     publicStruct := GeneratePublicKey(pvtkey)
//     pubkey := append(publicStruct.X.Bytes(), publicStruct.Y.Bytes()...)

//     fmt.Println(fmt.Sprintf("%d , %x",pvtkey,pubkey))

// } // HERE MAIN()
