package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"crypto/elliptic"
	// "regexp"
	"math/big"
	"crypto/ecdsa"
    "crypto/rand"
	"time"
	// "github.com/mr-tron/base58"
	"log"
	// api "pro/web"
)

var difficulty int = 5


type Block struct {
	Index     int      `json:"index"`
	Timestamp string   `json:"timestamp"`
	Votes     []Vote  	`json:"votes"`
	Nonce     int      `json:"nonce"`
	PrevHash  string   `json:"prevhash"`
	Hash      string   `json:"hash"`
}


type Vote struct { // add timestamp of transaction
	TXID		string		`json:"txhash"`
	Voter 		VoterInfo	`json:"voter"`
	Candidate 	string		`json:"candidate"`
	Status 		bool		`json:"status"`
	// Value 		int			`json:"value"`
}


// GODLEVELL STUFF ON ERORS : https://dave.cheney.net/2016/04/27/dont-just-check-errors-handle-them-gracefully

type VoterInfo struct {
	Address 	string 		`json:"address"`
	PublicKey 	string 		`json:"pubkey"`
	Signature 	string 		`json:"signature"`
}


func CalculateTXN_HASH(vtx Vote) string {
	record := vtx.Voter.Address + vtx.Candidate + strconv.FormatBool(vtx.Status)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}


var Blockchain []Block

func Getlocaltime() string {
	loc, _ := time.LoadLocation("Asia/Kolkata")
	now := time.Now().In(loc)
	// return now.Format("2006-01-02 15:04:05.000000")
	return now.String()
}

// func CoinbaseVote() *Vote {

// 	cb := &Vote{
// 		Voter:     "me",
// 		Candidate: "anu"
// 	}

// 	return cb
// }

func Genesisblock() {

	if len(Blockchain) != 0 {
		// fmt.Println("first block")
		return
	}
	bloc := Block{}

	// t := Getlocaltime()

	vinfo := VoterInfo{"VOTER_ADDRESS","VOTER_PUBLIC_KEY","SIGNATURE_PLUS_R"}

	cb := Vote{
		Voter:     vinfo,
		Candidate: "CANDIDATE_ADDRESS",
		Status:		true ,

	}
	cb.TXID = CalculateTXN_HASH(cb)

	bloc = Block{
		Index:     0,
		Timestamp: Getlocaltime(),
		Votes:      []Vote{cb},
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
	// r, _ := regexp.Compile("^0{+strconv.Itoa(difficulty)+}")
	// r, _ := regexp.Compile("^xxx")
	// return r.MatchString(hash)

	prefix := strings.Repeat("0", difficulty)
	// prefix := "00"
	return strings.HasPrefix(hash, prefix)
}

func WalletStatus(address string) bool {

	// if !ValidateAddress(address) {
	// 	return false , errors.New("NOTFOUND")
	// }

	for _, block := range Blockchain {
		for _, vtx := range block.Votes {
			if vtx.Voter.Address == address {
				return true
			}
		}
	}

	return false
}

func MineBlock(nblk Block) (int, string) {
	better_hash := nblk.Hash
	nblk.Nonce = 0

	for {
		
		better_hash = CalHash(nblk)
		// fmt.Println(nblk.Nonce, better_hash)
		if HashVali(better_hash) == false {
			nblk.Nonce++
			continue
		} else {
			break
		}
	}
	time.Sleep(2 * time.Second)
	return nblk.Nonce, better_hash

}

func (vtx *Vote) Sign(privKey ecdsa.PrivateKey , txhash string) {

	r, s, err := ecdsa.Sign(rand.Reader, &privKey, []byte(txhash) )
	if err != nil {
		panic(err)
	}
	signatureplusr := append(r.Bytes(), s.Bytes()...)
		// fmt.Printf("signature: %x\n", sig) OR including r ?? idk
		// we need BOTH , because verify ke time r aur sig dono params mai hain!!
		// ex. : ecdsa.Verify(&PVT.PublicKey, hash[:], r, sig)

	vtx.Voter.Signature = fmt.Sprintf("%x",signatureplusr)


}

func Verify(vtx Vote) bool {
	// txCopy := tx.TrimmedCopy()
	// curve := elliptic.P256()

	// for inID, vin := range tx.Vin {

		// prevTx := prevTXs[hex.EncodeToString(vin.Txid)]

		// refVoutPubKeyHash := prevTx.Vout[vin.Vout].PubKeyHash

		// // check that the spend coin is owned by vin.PubKey
		// if !bytes.Equal(PublicKeyHash(vin.PubKey), refVoutPubKeyHash) {
		// 	return false
		// }

		// txCopy.Vin[inID].Signature = nil
		// // txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout].PubKeyHash
		// txCopy.Vin[inID].PubKey = refVoutPubKeyHash
		// txCopy.ID = txCopy.Hash() // txID hash mil gayi 

		// txCopy.Vin[inID].PubKey = nil

		// idhar r aur sig nikal lena hai BIGsignature se 
		r := big.Int{}
		s := big.Int{}

		signatureplusrINbYTES := HexDecode(vtx.Voter.Signature)
		// fmt.Println(vtx.Voter.Signature , fmt.Sprintf("%s",signatureplusrINbYTES) )
		sigLen := len(signatureplusrINbYTES)
		r.SetBytes([]byte(signatureplusrINbYTES)[:(sigLen / 2)])
		s.SetBytes(signatureplusrINbYTES[(sigLen / 2):])

		// idhar (x,y) ki zaroorat hai &publickeyStruct banane mai
		// jo publickey-byte version se nikala 
		x := big.Int{}
		y := big.Int{}
		PubkeyINbYtes := HexDecode(vtx.Voter.PublicKey)
		keyLen := len(PubkeyINbYtes)
		x.SetBytes(PubkeyINbYtes[:(keyLen / 2)])
		y.SetBytes(PubkeyINbYtes[(keyLen / 2):])

		rawPubKey := ecdsa.PublicKey{elliptic.P256(), &x, &y}

		if ecdsa.Verify(&rawPubKey, []byte(vtx.TXID), &r, &s) == false {
			return false
		}
	// }

	return true
}


func NewTXN(voterID string, candidateID string) (Vote , bool) {

	

	// fortestonly
	w := MakeWallet()
	// vinfo := VoterInfo{voterID,w.PublicKey,"signature"}
	voterID = fmt.Sprintf("%s",w.Address())

	vinfo := VoterInfo{
		Address:	voterID,
		PublicKey:	fmt.Sprintf("%x",w.PublicKey),
	}


	vtx := Vote{
		Voter:     vinfo,
		Candidate: candidateID,
		Status:		true ,
	}
	vtx.TXID = CalculateTXN_HASH(vtx)

	vtx.Sign(w.PrivateKey,vtx.TXID) // sets signature to sign+r !! we need r in verify

	return vtx , Verify(vtx)

}

// func CandidateBlock(voterID string, candidateID string ,Prevblock Block ) (Block ) {
	

// 	// var blk_new Block

// 	tx , Verify_Signature_Status := NewTXN(voterID , candidateID) // new txn
// 	candyBloc := Block{}

// 	if !Verify_Signature_Status {
// 		return
// 	}

// 	// vinfo := VoterInfo{voterID,"pubkey","signature"}

// 	// // t := Getlocaltime()
// 	// tx := Vote{
// 	// 	Voter:     vinfo,
// 	// 	Candidate: candidateID,
// 	// 	Value:		1 ,

// 	// }

// 	// tx.TXID = CalculateTXN_HASH(tx)

// 	candyBloc = Block{
// 		Index:     Prevblock.Index + 1,
// 		Timestamp: Getlocaltime(),
// 		Votes:      []Vote{tx},
// 		// Nonce:     0,
// 		PrevHash:  Prevblock.Hash,
// 		// Hash:      CalHash(bloc),
// 	}

// 	return candyBloc
// }




func Addnewblock(VOTER_ADDRESS string, CANDY_ADDRESS string) (bool, error, string) {

	if !ValidateAddress(VOTER_ADDRESS){
		// return false , errors.New("Voter Address")
		return false , fmt.Errorf("!Invalid Voter Address : %s ",VOTER_ADDRESS) , "NAN"

	} 

	// else if !ValidateAddress(CANDY_ADDRESS){
	// 	return false , fmt.Errorf("!Invalid Candidate Address : %s ",CANDY_ADDRESS) , "NAN"
	// }


	tx , Verify_Signature_Status := NewTXN(VOTER_ADDRESS , CANDY_ADDRESS)
	if !Verify_Signature_Status {
		return false , fmt.Errorf("Signature Verification Error : false ") , "NAN"
	}
	// fmt.Println(tx)

	Prevblock := Blockchain[len(Blockchain)-1]

	// blk_new := CandidateBlock(voterID , candidateID , Prevblock)
	blk_new := Block{}

	blk_new = Block{
		Index:     Prevblock.Index + 1,
		Timestamp: Getlocaltime(),
		Votes:      []Vote{tx},
		// Nonce:     0,
		PrevHash:  Prevblock.Hash,
		// Hash:      CalHash(bloc),
	}

	// t := time.Now()

	// blk_new.Index = Prevblock.Index + 1
	// blk_new.Timestamp = Getlocaltime()
	// cb := &Vote{
	// 	Voter:     voterID,
	// 	Candidate: candidateID,
	// }

	// blk_new = Block{
	// 	Votes:      []*Vote{cb},
	// }
	// blk_new.Votes.Voter = voterID
	// blk_new.Votes.Candidate = candidateID
	// blk_new.PrevHash = Prevblock.Hash
	blk_new.Nonce, blk_new.Hash = MineBlock(blk_new)
	// fmt.Println(blk_new.Index,blk_new)

	// adjust settings before next mining
	// adjustdiff()
	

	// blk_new.Nonce =
	// blk_new.Hash = CalHash(blk_new)

	// verify
	if !Valid(blk_new, Prevblock) {
		// fmt.Println("invalid??")
		return false , fmt.Errorf("Block is Invalid!") , "NAN"
	}
	// now append it (maybe idk)
	Blockchain = append(Blockchain, blk_new)
	// time.Sleep(2 * time.Second)

	latest_Hash := Blockchain[len(Blockchain)-1].Hash
	fmt.Println("New Block Added " , blk_new.Index ,blk_new.Hash , UnixTime(blk_new.Timestamp))
	// Top()

	if latest_Hash == blk_new.Hash {
		return true , nil , latest_Hash
	} else {
		return false , fmt.Errorf("Error : Block Not Added to Blockchain ") , "NAN"
	}



}

func CalHash(thisblock Block) string {

	// Hash of Transaction will be calculated differently : MERKLE TREE (LATER) :: REMOVE VOTER/CANDIDATE_ID for now
	record := strconv.Itoa(thisblock.Index) + thisblock.Timestamp + thisblock.PrevHash + strconv.Itoa(thisblock.Nonce)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func Valid(newblk, prevblk Block) bool {
	if prevblk.Index+1 != newblk.Index {
		fmt.Println("1",prevblk.Index+1,newblk.Index)
		return false
	} else if newblk.PrevHash != prevblk.Hash {
		print("2")
		return false
	} else if CalHash(newblk) != newblk.Hash {
		print("3")
		return false
	}
	return true
}

func print(s string){
	fmt.Println(s)
}
func Handle(err error) {
    if err != nil {
        log.Panic(err)
    }
}

func PrintblockchainStdout() {
	bb, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(bb))
}


func adjustdiff() {

	length := len(Blockchain)
	lasttime := UnixTime(Blockchain[0].Timestamp)
	thistime := 420
	// fmt.Println(lasttime)
	tt := 0


	// currently loops whole blockchain , later will cut it down to last 10-20

	for _, block := range Blockchain[1:] {

		thistime = UnixTime(block.Timestamp)
		tt = tt + (thistime - lasttime)
		lasttime = thistime
		// fmt.Println(thistime , lasttime ,tt)
	}
	// fmt.Println(lasttime,thistime)

	var avgt float64 = float64(tt)/float64(length)
	
	if avgt > 7 {
		difficulty = difficulty-1
	} else if avgt < 1 {
		// fmt.Println("here")
		difficulty++
	}
	// fmt.Println("AvgTime : ",avgt, difficulty)
	fmt.Printf("AvgTime : %.2fs , Difficulty : %d   " , avgt , difficulty)

}
// const longForm = ""
func UnixTime(tim string) int {
	loc, _ := time.LoadLocation("Asia/Kolkata")
	// 2021-10-08 19:55:56.7413308 +0530 IST
	lay := "2006-01-02 15:04:05 MST"
	// t, err := time.Parse(lay, "2021-10-08 20:11:06 +0530 IST")
	t, err := time.ParseInLocation(lay,strings.Replace(tim, "+0530", "", -1), loc)


	// t, err := time.Parse(lay, tim)
	if err != nil {
        fmt.Println(err)
    }
	return int(t.UTC().Unix())
}