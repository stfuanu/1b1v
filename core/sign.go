
package core

import (
    // "crypto/ecdsa"
    // "crypto/rand"
    // "crypto/elliptic"
    // "crypto/sha256"
    // "encoding/hex"
    "fmt"
    // "log"
    // "math/big"

    // "golang.org/x/crypto/ripemd160"
    // "github.com/mr-tron/base58"

)

func too(){
	fmt.Println("he")
}

// func (in *TXInput) UsesKey(pubKeyHash []byte) bool {
// 	lockingHash := HashPubKey(in.PubKey)

// 	return bytes.Compare(lockingHash, pubKeyHash) == 0
// }



// func (out *TXOutput) Lock(address []byte) { // recipent address
// 	pubKeyHash := Base58Decode(address)
// 	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]
// 	out.PubKeyHash = pubKeyHash
// }

// func (out *TXOutput) IsLockedWithKey(pubKeyHash []byte) bool {
// 	return bytes.Compare(out.PubKeyHash, pubKeyHash) == 0
// }


// func (bc *Blockchain) SignTransaction(tx *Vote, privKey ecdsa.PrivateKey) {
// 	prevTXs := make(map[string]Vote)

// 	for _, vin := range tx.Vin {
// 		prevTX, err := bc.FindTransaction(vin.Txid)
// 		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
// 	}

// 	tx.Sign(privKey, prevTXs)
// }

// func (bc *Blockchain) VerifyTransaction(tx *Vote) bool {
// 	prevTXs := make(map[string]Vote)

// 	for _, vin := range tx.Vin {
// 		prevTX, err := bc.FindTransaction(vin.Txid)
// 		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
// 	}

// 	return tx.Verify(prevTXs)
// }

// func (in *TXInput) CanUnlockOutputWith(addr string) bool {
// 	return in.ScriptSig == unlockingData
// }

// func (out *TXOutput) CanBeUnlockedWith(addr string) bool {
// 	return out.ScriptPubKey == unlockingData
// }

// func (tx *Transaction) Sign(privKey ecdsa.PrivateKey, prevTXs map[string]Transaction) {
// 	// if tx.IsCoinbase() {
// 	// 	return
// 	// }

// 	// The method takes a private key and a map of previous transactions. 
// 	// As mentioned above, in order to sign a transaction, 
// 	// we need to access the outputs referenced in the inputs of the transaction, 
// 	// thus we need the transactions that store these outputs.

// 	txCopy := tx.TrimmedCopy() // we trim our txn becoz , signature can contain only 
// 	// things which can be shared ! (amount , from , to) exclude signature & also pvtkey

// 	for inID, vin := range txCopy.Vin {
// 		prevTx := prevTXs[hex.EncodeToString(vin.Txid)]
// 		txCopy.Vin[inID].Signature = nil
// 		txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout].PubKeyHash

// 		txCopy.ID = txCopy.Hash()
// 		fmt.Println("TXID : ", txCopy.ID)
// 		txCopy.Vin[inID].PubKey = nil

// 		r, s, err := ecdsa.Sign(rand.Reader, &privKey, txCopy.ID)
// 		if err != nil {
// 			panic(err)
// 		}
// 		signatureplusr := append(r.Bytes(), s.Bytes()...)
// 		// fmt.Printf("signature: %x\n", sig) OR including r ?? idk
// 		// we need BOTH , because verify ke time r aur sig dono params mai hain!!
// 		// ex. : ecdsa.Verify(&PVT.PublicKey, hash[:], r, sig)

// 		tx.Vin[inID].Signature = signatureplusr
// 	}
// }

// func (tx *Transaction) Verify(prevTXs map[string]Transaction) bool {
// 	txCopy := tx.TrimmedCopy()
// 	curve := elliptic.P256()

// 	for inID, vin := range tx.Vin {

// 		prevTx := prevTXs[hex.EncodeToString(vin.Txid)]

// 		refVoutPubKeyHash := prevTx.Vout[vin.Vout].PubKeyHash

// 		// check that the spend coin is owned by vin.PubKey
// 		if !bytes.Equal(PublicKeyHash(vin.PubKey), refVoutPubKeyHash) {
// 			return false
// 		}

// 		txCopy.Vin[inID].Signature = nil
// 		// txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout].PubKeyHash
// 		txCopy.Vin[inID].PubKey = refVoutPubKeyHash
// 		txCopy.ID = txCopy.Hash() // txID hash mil gayi 

// 		txCopy.Vin[inID].PubKey = nil

// 		// idhar r aur sig nikal lena hai BIGsignature se 
// 		r := big.Int{}
// 		s := big.Int{}
// 		sigLen := len(vin.Signature)
// 		r.SetBytes(vin.Signature[:(sigLen / 2)])
// 		s.SetBytes(vin.Signature[(sigLen / 2):])

// 		// idhar (x,y) ki zaroorat hai &publickeyStruct banane mai
// 		// jo publickey-byte version se nikala 
// 		x := big.Int{}
// 		y := big.Int{}
// 		keyLen := len(vin.PubKey)
// 		x.SetBytes(vin.PubKey[:(keyLen / 2)])
// 		y.SetBytes(vin.PubKey[(keyLen / 2):])

// 		rawPubKey := ecdsa.PublicKey{curve, &x, &y}
// 		if ecdsa.Verify(&rawPubKey, txCopy.ID, &r, &s) == false {
// 			return false
// 		}
// 	}

// 	return true
// }