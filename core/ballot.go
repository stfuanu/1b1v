package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strconv"
	"strings"
)

type Ballot struct {
	ElectionName    string    `json:"name"`
	Candidates      []string  `json:"candidates"`
	TotalCandidates int       `json:"totalcandidates"`
	StartTimeStamp  string    `json:"start"`
	EndTimeStamp    string    `json:"end"`
	Owner           VoterInfo `json:"Owner"`
	ContractHash    string    `json:"contract"`
}

var Ballots []Ballot

func CreateBallots() Ballot {

	w := MakeWallet()
	own := VoterInfo{
		Address:   fmt.Sprintf("%s", w.Address()),
		PublicKey: fmt.Sprintf("%x", w.PublicKey),
	}
	// signature will be added later with signBallot method theek!!!

	NewBallot := Ballot{
		ElectionName: "",
		Candidates:   []string{""},
		// TotalCandidates: len(),
		StartTimeStamp: "",
		EndTimeStamp:   "",
		Owner:          own,
		// ContractHash:    "",
	}

	NewBallot.TotalCandidates = len(NewBallot.Candidates)
	NewBallot.ContractHash = CalContractHash(NewBallot)

	NewBallot.SignBallot(w.PrivateKey, NewBallot.ContractHash)

	return NewBallot

	// push this txn to votes.json too
}

func (btx *Ballot) SignBallot(privKey ecdsa.PrivateKey, contract_hash string) {

	r, s, err := ecdsa.Sign(rand.Reader, &privKey, []byte(contract_hash))
	if err != nil {
		panic(err)
	}
	signatureplusr := append(r.Bytes(), s.Bytes()...)
	// fmt.Printf("signature: %x\n", sig) OR including r ?? idk
	// we need BOTH , because verify ke time r aur sig dono params mai hain!!
	// ex. : ecdsa.Verify(&PVT.PublicKey, hash[:], r, sig)

	btx.Owner.Signature = fmt.Sprintf("%x", signatureplusr)
}
func VerifyBallot(btx Ballot) bool {
	r := big.Int{}
	s := big.Int{}

	signatureplusrINbYTES := HexDecode(btx.Owner.Signature)
	sigLen := len(signatureplusrINbYTES)
	r.SetBytes([]byte(signatureplusrINbYTES)[:(sigLen / 2)])
	s.SetBytes(signatureplusrINbYTES[(sigLen / 2):])
	x := big.Int{}
	y := big.Int{}
	PubkeyINbYtes := HexDecode(btx.Owner.PublicKey)
	keyLen := len(PubkeyINbYtes)
	x.SetBytes(PubkeyINbYtes[:(keyLen / 2)])
	y.SetBytes(PubkeyINbYtes[(keyLen / 2):])

	rawPubKey := ecdsa.PublicKey{elliptic.P256(), &x, &y}

	return ecdsa.Verify(&rawPubKey, []byte(btx.ContractHash), &r, &s)
}

func CalContractHash(bb Ballot) string {

	var sss strings.Builder
	for _, s := range bb.Candidates {
		// fmt.Println(s)
		sss.WriteString(s)
	}

	record := bb.ElectionName + bb.StartTimeStamp + bb.EndTimeStamp + bb.Owner.Address + bb.Owner.PublicKey + bb.Owner.Signature + sss.String() + strconv.Itoa(bb.TotalCandidates)
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func ContractSafe(contra string) bool {
	var findmyBallot Ballot
	for i, s := range Ballots {
		if s.ContractHash == contra {
			findmyBallot = Ballots[i]
			break
		}
	}
	// findmyBallot.ContractHash = ""
	// contract hash ko salt hi nahi kr rahe toh ye kuu krna hai

	return contra == CalContractHash(findmyBallot)
}

func AddNewBallot(Blt Ballot) {

	// t := []string{"g", "h", "i"}

	// verifyhere

	// blt := &Ballot{"name", t, "344343", "4343434", VoterInfo{"sjja", "saa", "ajsajjas"}, "jjjjqq"}

	Ballots = append(Ballots, Blt)
	file, _ := json.MarshalIndent(Ballots, "", " ")

	err := ioutil.WriteFile("ballots.json", file, 0644)
	if err != nil {
		log.Println(err)
	}
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
