package core

import (
	// "crypto/ecdsa"
	// "crypto/rand"
	// "crypto/elliptic"
	// "crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

	return fmt.Sprintf("%s", decoded)

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

func BallotFileToArray(path string) []Ballot {
	var LoadBallots, ball []Ballot
	// var ball []Ballot
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Print(err)
	}
	err = json.Unmarshal(data, &ball)
	if err != nil {
		fmt.Println("error:", err)
	}
	for i := range ball {
		LoadBallots = append(LoadBallots, ball[i])
	}
	return LoadBallots
}

func BlockchainFileToArray(path string) []Block {
	var LoadArray, object []Block
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Print(err)
	}
	err = json.Unmarshal(data, &object)
	if err != nil {
		fmt.Println("error:", err)
	}
	for i := range object {
		LoadArray = append(LoadArray, object[i])
	}
	return LoadArray
}
