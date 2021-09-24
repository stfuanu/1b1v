package main

import (
	"fmt"
	"net/http"
)

func Handle_NAME(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "anu!!!!!!!!!")
}

func main() {
	http.HandleFunc("/", Handle_NAME)
	http.ListenAndServe(":80", nil)

}
