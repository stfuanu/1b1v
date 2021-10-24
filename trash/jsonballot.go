package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/mr-tron/base58"
)

type Ballot struct {
	ElectionName    string   `json:"name"`
	Candidates      []string `json:"candidates"`
	TotalCandidates int      `json:"totalcandidates"`
	StartTimeStamp  string   `json:"start"`
	EndTimeStamp    string   `json:"end"`
}

func main() {

	NewBallot := Ballot{
		ElectionName:   "WHO'S THE BEST COOK ?",
		Candidates:     []string{"12tmRt6AADfQhfruF3RzFDdNhjiSEkwMvF", "1DngEcP2tCkxZNiAmm3Ar8VXXAAvAPfm8E", "1HRK5H21wFguq5ecJF8FvQk28qYnPz1Qb9"},
		StartTimeStamp: "1635032651",
		EndTimeStamp:   "1635043569",
	}
	NewBallot.TotalCandidates = len(NewBallot.Candidates)

	jsonString, _ := json.Marshal(NewBallot)
	enco := string(base58Encode(jsonString))
	fmt.Println(enco)

	//37EuM2iWfq5VzDyvBVPnaAsdD8steUBYqNiLfYjcJJ1rVoYWaoVBqWn89qZAvmC7Up34GNcmYQY5soD9vXyscz4WvH3qxaqnFrF92tmd3L8S9JKgrCJT1nRdK3MgmqvEaSwLAJdUZAMBmJpnBDavLKjLg1rEnoifaHqFhrWsXDMyDGVexQaoU9K3J

	deco := base58Decode([]byte(enco))
	fmt.Println(string(deco))

}

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
