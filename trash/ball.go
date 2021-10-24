package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type VoterInfo struct {
	Address   string `json:"address"`
	PublicKey string `json:"pubkey"`
	Signature string `json:"signature"`
}

type Ballot struct {
	ElectionName   string    `json:"name"`
	Candidates     []string  `json:"candidates"`
	StartTimeStamp string    `json:"start"`
	EndTimeStamp   string    `json:"end"`
	Owner          VoterInfo `json:"Owner"`
	ContractHash   string    `json:"contract"`
}

var Ballots []Ballot

func main() {
	t := []string{"g", "h", "i"}
	// var b []string

	blt := &Ballot{"name", t, "344343", "4343434", VoterInfo{"sjja", "saa", "ajsajjas"}, "jjjjqq"}
	blt2 := &Ballot{"name2", t, "344343", "4343434", VoterInfo{"sjja", "saa", "ajsajjas"}, "jjjjqq"}
	b := AddNewBallot(blt)
	b = AddNewBallot(blt2)

	// PrintblockchainStdout()

	file, _ := json.MarshalIndent(b, "", " ")

	err := ioutil.WriteFile("sa.json", file, 0644)

	// err := ioutil.WriteFile("sa.json", []byte(b), 0644)
	if err != nil {
		panic(err)
	}

	// a := LoadBallot()
	// fmt.Println(a)
	LoadBallot()

}
func AddNewBallot(Blt *Ballot) []Ballot {

	Ballots = append(Ballots, *Blt)
	return Ballots
}

func LoadBallot() {

	// var mytype map[string]string

	var LoadBallots []Ballot

	var ball []Ballot
	data, err := ioutil.ReadFile("sa.json")
	if err != nil {
		fmt.Print(err)
	}
	// var obj DayPrice

	// unmarshall it

	err = json.Unmarshal(data, &ball)
	if err != nil {
		fmt.Println("error:", err)
	}
	for i := range ball {
		LoadBallots = append(LoadBallots, ball[i])
	}
	bb, err := json.MarshalIndent(LoadBallots, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(bb))

	fmt.Println(LoadBallots)
}

func PrintblockchainStdout() {
	bb, err := json.MarshalIndent(Ballots, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(bb))
}
