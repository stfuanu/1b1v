package main

import (
	"fmt"
	"math/rand"
	core "pro/core"
	api "pro/web"
	"time"
)

var (
	addedORnot bool
	err        error
	hashifany  string
)

func main() {
	core.Init()
	rand.Seed(time.Now().UnixNano())
	var randnum int

	core.Genesisblock()
	// core.Printblockchain()

	// addedORnot, err, hashifany = core.Addnewblock("BALLOT", "19yaXUBokMBzdqFex5qpZPwvV3CStnRVff", "SMART_CONTRACT", "9iZ33a27vHsxkNW4Pvrawrr9PY9AZJusCaukmJy3mFrLsDt29duGUV2Y43HjCf2jzDUzHcJppLa4WJ3rRPLr1YY8u45ZK64i17kHk4mKu54tHQR24pnqkkwX5oDUGaGKPs1LAzVikCqPV7eukAGMHcgvuVVfm3Yoca9g6QEyxKNfkVzffERM9muZQLmmmJZU6ZrBXfRhA6YkjCXA7qrpFMfjzSjQN21oYHcgf1X1VzfHUwCHqP4XW9fAJFDsyqnDkdEmTMmz4omdECBQy6zocixnegUsbUvcatVdaBG7Y8")
	// fmt.Println(addedORnot, err, hashifany)

	Candidates := []string{"12tmRt6AADfQhfruF3RzFDdNhjiSEkwMvF", "1HRK5H21wFguq5ecJF8FvQk28qYnPz1Qb9", "1DngEcP2tCkxZNiAmm3Ar8VXXAAvAPfm8E"}

	for i := 1; i < 5; i++ {
		randnum = rand.Intn(2-0+1) + 0
		addedORnot, err, hashifany = core.Addnewblock("VOTE", "19yaXUBokMBzdqFex5qpZPwvV3CStnRVff", Candidates[randnum], "4191a0fc9cabc39454827d41ac33137ca92d8710e5930a9653bf16afc44a7e0f")
		fmt.Println(addedORnot, err, hashifany)
	}

	core.PrintblockchainStdout()
	api.StartServer()

}

// curl -X POST -H "content-type: application/json"  http://localhost/vote/new -d "{\"address\": \"anu\",\"candidate\": \"Z\"}"

// 12tmRt6AADfQhfruF3RzFDdNhjiSEkwMvF , 1DngEcP2tCkxZNiAmm3Ar8VXXAAvAPfm8E , 1HRK5H21wFguq5ecJF8FvQk28qYnPz1Qb9
// {"name":"WHO'S THE BEST COOK ?","candidates":["12tmRt6AADfQhfruF3RzFDdNhjiSEkwMvF","1DngEcP2tCkxZNiAmm3Ar8VXXAAvAPfm8E","1HRK5H21wFguq5ecJF8FvQk28qYnPz1Qb9"],"totalcandidates":3,"start":"1635032651","end":"1635043569"}
// 9iZ33a27vHsxkNW4Pvrawrr9PY9AZJusCaukmJy3mFrLsDt29duGUV2Y43HjCf2jzDUzHcJppLa4WJ3rRPLr1YY8u45ZK64i17kHk4mKu54tHQR24pnqkkwX5oDUGaGKPs1LAzVikCqPV7eukAGMHcgvuVVfm3Yoca9g6QEyxKNfkVzffERM9muZQLmmmJZU6ZrBXfRhA6YkjCXA7qrpFMfjzSjQN21oYHcgf1X1VzfHUwCHqP4XW9fAJFDsyqnDkdEmTMmz4omdECBQy6zocixnegUsbUvcatVdaBG7Y8
