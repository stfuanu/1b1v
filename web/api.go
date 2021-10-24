package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	// "errors"
	core "pro/core"

	"github.com/gorilla/mux"
)

// w.Write([]byte("Gorilla!\n"))

type Jsondata struct {
	Voter     string `json:"voter"`
	Candidate string `json:"candidate"`
	contra    string `json:"contract"`
}

type BallData struct {
	Voter  string `json:"voter"`
	contra string `json:"contract"` // candidate to default hi rahega na
}

type ResponseToVoter struct {
	Status    int    `json:"status"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
	Hash      string `json:"hash,omitempty"`
}

func GetBlockchain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	bb, err := json.MarshalIndent(core.Blockchain, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, string(bb))
}

func GetBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	reqhash := mux.Vars(r)
	// fmt.Println(reqhash)

	for _, block := range core.Blockchain {
		if block.Hash == reqhash["hash"] {
			blk, err := json.MarshalIndent(block, "", "  ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			io.WriteString(w, string(blk))

		}
	}

}

func AppendNewBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	defer r.Body.Close()
	if r.Header.Get("Content-type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		w.Write([]byte("415 - Unsupported Media Type. Only JSON files are allowed"))
		// return
	} else if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed."))
	} else {

		var newvote Jsondata

		// error :- web\api.go:75:24: cannot convert r.Body (type io.ReadCloser) to type []byte
		// note :- ye wala (io.reader) https://pkg.go.dev/encoding/json#NewDecoder

		abc := json.NewDecoder(r.Body) // outpts pointer

		errorAsreturn := abc.Decode(&newvote)
		// json.Unmarshal([]byte(r.Body), &newvote)
		// or maybe,,,, json.Unmarshal([]byte(r.Body.String()), &newvote)
		// err := decoder.Decode(&newvote);
		// http.StatusOK
		if errorAsreturn != nil {
			log.Fatal(errorAsreturn)
		}

		// if err != nil {
		// 	// panic(err)
		// 	fmt.Println(err)
		// 	// w.Write([]byte(err))
		//     return
		// }

		// New Block --->
		addedORnot, err, hashifany := core.Addnewblock("VOTE", newvote.Voter, newvote.Candidate, newvote.contra)

		if addedORnot && err == nil {
			// fmt.Println("sukcess" , hashifany)
			io.WriteString(w, WhatHappened(http.StatusOK, "Success", hashifany))
			// w.Write([]byte("Method not allowed."))

		} else {
			// fmt.Println("NoHash" , hashifany)
			fullMessage := fmt.Sprintf("Failed : %v", err)
			io.WriteString(w, WhatHappened(http.StatusOK, fullMessage, hashifany))

		}

		// This will happen from funk.go
		// dat := WhatHappened(http.StatusOK, "Success")
		// bb, err := json.MarshalIndent(dat, "", "  ")
		// fmt.Println(string(bb))
	}

}

func WhatHappened(statuscode int, mess string, hashh string) string {
	// data := `{"status-sode": "%d", "message": "failed"}`
	// data := fmt.Sprintf(`{"status": "%d", "message": "%s"}`, statuscode, mess)

	data := &ResponseToVoter{
		Status:    statuscode,
		Message:   mess,
		Timestamp: core.Getlocaltime(),
		// Hash:      "newhash",
	}

	if hashh != "NAN" {
		data.Hash = hashh
	}

	// bb, err := json.MarshalIndent(data, "", "  ")
	// if err != nil {
	// 	fmt.Println(err)
	// 	// return
	// }
	// return *data
	bb, err := json.MarshalIndent(*data, "", "  ")
	// if err != nil {
	//     fmt.Println(err)
	// }
	core.Handle(err)
	// io.WriteString(w, string(bb))
	return string(bb)
}

func NewBallot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	defer r.Body.Close()
	if r.Header.Get("Content-type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		w.Write([]byte("415 - Unsupported Media Type. Only JSON files are allowed"))
		// return
	} else if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("Method not allowed."))
	} else {

		var NewBallot BallData
		errorAsreturn := json.NewDecoder(r.Body).Decode(&NewBallot)
		if errorAsreturn != nil {
			log.Fatal(errorAsreturn)
		}
		// jsonString, _ := json.Marshal(NewBallot)

		addedORnot, err, hashifany := core.Addnewblock("BALLOT", NewBallot.Voter, "SMART_CONTRACT", NewBallot.contra)

		if addedORnot && err == nil {
			io.WriteString(w, WhatHappened(http.StatusOK, "Success", hashifany))

		} else {
			fullMessage := fmt.Sprintf("Failed : %v", err)
			io.WriteString(w, WhatHappened(http.StatusOK, fullMessage, hashifany))

		}
	}

}

//external call , bahar se hi bsse58 bankr aana bhai

func StartServer() {
	routervar := mux.NewRouter()

	routervar.HandleFunc("/api/votes.json", GetBlockchain).Methods("GET")
	routervar.HandleFunc("/api/vote/{hash}", GetBlock).Methods("GET")
	routervar.HandleFunc("/vote/newvtx", AppendNewBlock).Methods("POST")
	routervar.HandleFunc("/vote/newbtx", NewBallot).Methods("POST")

	log.Fatal(http.ListenAndServe(":80", routervar))
}
