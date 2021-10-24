package core

import (
	"fmt"
)

// type Ballot struct {
// 	ElectionName    string   `json:"name"`
// 	Candidates      []string `json:"candidates"`
// 	TotalCandidates int      `json:"totalcandidates"`
// 	StartTimeStamp  string   `json:"start"`
// 	EndTimeStamp    string   `json:"end"`
// }

func aa() {
	fmt.Println("ss")
}

// func concheck(hash string) { // abhi ke liye toh yahi chek hai , baad mai , owner bhi check kr sakte (3 se jyada contract naahi bna sakta ya aisa kuch)
// 	for _, block := range Blockchain {
// 		for _, btx := range block.Votes {
// 			// switch
// 			if btx.Owner == address && vtx.Contract == contract {
// 				return true
// 			}
// 		}
// 	}
// }

// func AddNewBallot(NewBallot Ballot) (bool, error, string) {

// 	NewBallot.TotalCandidates = len(NewBallot.Candidates)

// 	return true, nil, Newb.ContractHash
// }
