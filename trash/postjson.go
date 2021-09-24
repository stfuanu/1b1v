package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type test_struct struct {
	Test string
}

func parseGhPost(rw http.ResponseWriter, request *http.Request) {
	defer request.Body.Close()
	decoder := json.NewDecoder(request.Body)

	var t test_struct
	err := decoder.Decode(&t)

	if err != nil {
		panic(err)
	}

	fmt.Println(t.Test)
}

func main() {
	http.HandleFunc("/", parseGhPost)
	http.ListenAndServe(":8080", nil)
}


// curl -X POST -d "{\"test\": \"that\"}" http://localhost:8080

func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        var m Message

        decoder := json.NewDecoder(r.Body)
        if err := decoder.Decode(&m); err != nil {
                respondWithJSON(w, r, http.StatusBadRequest, r.Body)
                return
        }   
        defer r.Body.Close()

        //ensure atomicity when creating new block
        mutex.Lock()
        newBlock := generateBlock(Blockchain[len(Blockchain)-1], m.BPM)
        mutex.Unlock()

        if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
                Blockchain = append(Blockchain, newBlock)
                spew.Dump(Blockchain)
        }   

        respondWithJSON(w, r, http.StatusCreated, newBlock)

}