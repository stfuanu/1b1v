// package trash

// import (
// 	"crypto/sha256"
// 	"encoding/hex"
// 	"encoding/json"
// 	"fmt"
// 	"strconv"

// 	// "strconv"
// 	"time"
// )

// type VoteStat struct {
// 	Voter     string `json:"voter"`
// 	Candidate string `json:"candidate"`
// }

// type Block struct {
// 	Index     int      `json:"index"`
// 	Timestamp string   `json:"timestamp"`
// 	Vote      VoteStat `json:"votestat"`
// 	Hash      string   `json:"hash"`
// 	PrevHash  string   `json:"prevhash"`
// }

// var Blockchain []Block

// // SHA256 hasing
// func calculateHash(block Block) string {
// 	record := strconv.Itoa(block.Index) + block.Timestamp + block.Vote.Voter + block.Vote.Candidate + block.PrevHash
// 	h := sha256.New()
// 	h.Write([]byte(record))
// 	hashed := h.Sum(nil)
// 	return hex.EncodeToString(hashed)
// }

// func main() {
// 	t := getlocaltime()

// 	vs := &VoteStat{
// 		Voter:     "dkkdkw",
// 		Candidate: "dkjwkw",
// 	}
// 	bloc := &Block{
// 		Index:     0,
// 		Timestamp: t.Format("2006-01-02 15:04:05"),
// 		Vote:      *vs,
// 		Hash:      "kskllskd",
// 		PrevHash:  "jjkwjkw",
// 	}
// 	fmt.Println(bloc)
// 	bb, err := json.Marshal(bloc)
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	fmt.Println(string(bb))

// 	Blockchain = append(Blockchain, *bloc)
// 	fmt.Println(Blockchain)
// }

// func getlocaltime() time.Time {
// 	loc, _ := time.LoadLocation("Asia/Kolkata")
// 	now := time.Now().In(loc)
// 	return now
// }

// func generateBlock(oldBlock Block, BPM int) (Block, error) {

// 	var newBlock Block

// 	t := getlocaltime()

// 	newBlock.Index = oldBlock.Index + 1
// 	newBlock.Timestamp = t.String()
// 	newBlock.Vote.Voter = "djjwd"
// 	newBlock.Vote.Candidate = "skkwkw"
// 	newBlock.PrevHash = oldBlock.Hash
// 	newBlock.Hash = calculateHash(newBlock)

// 	return newBlock, nil
// }

// func genesisblock() Block {

// }
