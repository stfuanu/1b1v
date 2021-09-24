package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	// api "pro/web"
)

const difficulty int = 2

type VoteStat struct {
	Voter     string `json:"voterAddr"`
	Candidate string `json:"candidateAddr"`
}

type Block struct {
	Index     int      `json:"index"`
	Timestamp string   `json:"timestamp"`
	Vote      VoteStat `json:"vote"`
	Nonce     int      `json:"nonce"`
	PrevHash  string   `json:"prevhash"`
	Hash      string   `json:"hash"`
}






var Blockchain []Block

func Getlocaltime() string {
	loc, _ := time.LoadLocation("Asia/Kolkata")
	now := time.Now().In(loc)
	return now.Format("2006-01-02 15:04:05.000000")
}

func Genesisblock() {

	if len(Blockchain) != 0 {
		// fmt.Println("first block")
		return
	}
	bloc := Block{}
	// t := Getlocaltime()
	vs := VoteStat{
		Voter:     "anurag",
		Candidate: "candidateAddr",
	}
	bloc = Block{
		Index:     0,
		Timestamp: Getlocaltime(),
		Vote:      vs,
		// Nonce:     0,
		PrevHash:  "0",
		// Hash:      CalHash(bloc),
	}

	bloc.Nonce , bloc.Hash = MineBlock(bloc)

	// bloc = Block{
	// 	Nonce: noncee,
	// 	Hash: hashh,
	// }



	Blockchain = append(Blockchain, bloc)
}

func HashVali(hash string) bool {
	// r, _ := regexp.Compile("^0{4}")
	// return r.MatchString(hash)

	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

func MineBlock(nblk Block) (int, string) {
	better_hash := nblk.Hash
	nblk.Nonce = 0

	for {
		// fmt.Println(nblk.Nonce)
		better_hash = CalHash(nblk)
		if HashVali(better_hash) == false {
			nblk.Nonce++
			continue
		} else {
			break
		}
	}
	return nblk.Nonce, better_hash

}

func Addnewblock(voterID string, candidateID string) (bool, string) {

	Prevblock := Blockchain[len(Blockchain)-1]

	var blk_new Block

	// t := time.Now()

	blk_new.Index = Prevblock.Index + 1
	blk_new.Timestamp = Getlocaltime()
	blk_new.Vote.Voter = voterID
	blk_new.Vote.Candidate = candidateID
	blk_new.PrevHash = Prevblock.Hash

	blk_new.Nonce, blk_new.Hash = MineBlock(blk_new)

	fmt.Println("New Block Added " ,blk_new.Hash)

	// blk_new.Nonce =
	// blk_new.Hash = CalHash(blk_new)

	// verify
	if !Valid(blk_new, Prevblock) {
		return false , "NAN"
	}
	// now append it (maybe idk)
	Blockchain = append(Blockchain, blk_new)
	// time.Sleep(2 * time.Second)

	latest_Hash := Blockchain[len(Blockchain)-1].Hash

	if latest_Hash == blk_new.Hash {
		return true , latest_Hash
	} else {
		return false , "NAN"
	}

}

func CalHash(thisblock Block) string {
	record := strconv.Itoa(thisblock.Index) + thisblock.Timestamp + thisblock.Vote.Voter + thisblock.Vote.Candidate + thisblock.PrevHash + strconv.Itoa(thisblock.Nonce)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func Valid(newblk, prevblk Block) bool {
	if prevblk.Index+1 != newblk.Index {
		return false
	} else if newblk.PrevHash != prevblk.Hash {
		return false
	} else if CalHash(newblk) != newblk.Hash {
		return false
	}
	return true
}

func PrintblockchainStdout() {
	bb, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(bb))
}


