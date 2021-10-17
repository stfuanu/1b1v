// package core

// import (
//     "crypto/ecdsa"
//     "crypto/rand"
//     "crypto/elliptic"
//     "crypto/sha256"
//     "encoding/hex"
//     "fmt"
//     "log"
//     "math/big"

//     "golang.org/x/crypto/ripemd160"
//     "github.com/mr-tron/base58"

// )


// // can later add multiple []input/output (not needed in case of votes ig)
// type Vote struct {
// 	ID	[]byte 		`json:"ID"`
// 	Vin     []TXInput 	`json:"candidate"`
// 	Vout	[]TXOutput 	`json:"voter"`
// }

// // Considering that transactions unlock previous outputs, 
// // redistribute their values, and lock new outputs, 

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



// func (tx *Transaction) TrimmedCopy() Transaction {
// 	var inputs []TXInput
// 	var outputs []TXOutput

// 	for _, vin := range tx.Vin {
// 		inputs = append(inputs, TXInput{vin.Txid, vin.Vout, nil, nil})
// 	}

// 	for _, vout := range tx.Vout {
// 		outputs = append(outputs, TXOutput{vout.Value, vout.PubKeyHash})
// 	}p

// 	txCopy := Transaction{tx.ID, inputs, outputs}

// 	return txCopy
// }


// // We need to find all unspent transaction outputs (UTXO).
// // Unspent means that these outputs weren’t referenced in any inputs.


// func (bc *Blockchain) FindUTXO(address string) []TXOutput {
//        var UTXOs []TXOutput
//        unspentTransactions := bc.FindUnspentTransactions(address)

//        for _, tx := range unspentTransactions {
//                for _, out := range tx.Vout {
//                        if out.CanBeUnlockedWith(address) {
//                                UTXOs = append(UTXOs, out)
//                        }
//                }
//        }

//        return UTXOs
// }

// func (bc *Blockchain) FindSpendableOutputs(address string, amount int) (int, map[string][]int) {
// 	unspentOutputs := make(map[string][]int)
// 	unspentTXs := bc.FindUnspentTransactions(address)
// 	accumulated := 0

// Work: // this is called LABEL BREAKS (removes need for double breaks in "nested" /case/FOR-LOOPS !! )
// 	for _, tx := range unspentTXs {
// 		txID := hex.EncodeToString(tx.ID)

// 		for outIdx, out := range tx.Vout {
// 			if out.CanBeUnlockedWith(address) && accumulated < amount {
// 				accumulated += out.Value
// 				unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)

// 				if accumulated >= amount {
// 					break Work // breaks idhar se
// 				}
// 			}
// 		}
// 	}

// 	return accumulated, unspentOutputs
// }



// // func (bc *Blockchain) FindUnspentTransactions(address string) []Transaction {
// //   var unspentTXs []Transaction
// //   spentTXOs := make(map[string][]int)
// //   bci := bc.Iterator()

// //   for {
// //     block := bci.Next()

// //     for _, tx := range block.Transactions {
// //       txID := hex.EncodeToString(tx.ID)

// //     Outputs:
// //       for outIdx, out := range tx.Vout {
// //         // Was the output spent?
// //         if spentTXOs[txID] != nil {
// //           for _, spentOut := range spentTXOs[txID] {
// //             if spentOut == outIdx {
// //               continue Outputs
// //             }
// //           }
// //         }

// //         if out.CanBeUnlockedWith(address) {
// //           unspentTXs = append(unspentTXs, *tx)
// //         }
// //       }

// //       if tx.IsCoinbase() == false {
// //         for _, in := range tx.Vin {
// //           if in.CanUnlockOutputWith(address) {
// //             inTxID := hex.EncodeToString(in.Txid)
// //             spentTXOs[inTxID] = append(spentTXOs[inTxID], in.Vout)
// //           }
// //         }
// //       }
// //     }

// //     if len(block.PrevBlockHash) == 0 {
// //       break
// //     }
// //   }

// //   return unspentTXs
// // }

// func (bc *Blockchain) FindTransaction(ID []byte) (Vote, error) {
// 	// bci := bc.Iterator()

// 	for _, block := range core.Blockchain {
// 		// block := bci.Next()

// 		for _, vtx := range block.Votes {
// 			if bytes.Compare(vtx.ID, ID) == 0 {
// 				return *vtx, nil
// 			}
// 		}

// 		if len(block.PrevHash) == 0 {
// 			break
// 		}
// 	}

// 	return Transaction{}, errors.New("Transaction is not found")
// }

