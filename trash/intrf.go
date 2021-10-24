package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/mr-tron/base58"
)

type Foo struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
}

// interface{} is stored as a two word pair, one word describing the underlying type information and one word describing the data within that interface:

type Bar struct {
	N string `json:"n"`
	S int    `json:"s"`
}

var blockchain []interface{}

func main() {

	// for i := 0; i < 10; i++ {

	a := Bar{N: "3jjsk", S: 4}
	blockchain = append(blockchain, a)
	// blockchain = append(blockchain, Foo{1, "jsdk"})

	for _, v := range blockchain {
		switch c := v.(type) {
		case Foo:
			// fmt.Printf("%T , %v \n", v, v)

		case Bar:
			// fmt.Printf("%T , %v \n", v, v)
		default:
			fmt.Printf("Not sure what type ")
			fmt.Println(c)
		}

	}

	// }
	// var full = []datas

	jsonString, _ := json.MarshalIndent(a, "", "  ")
	// jsonString, _ := json.MarshalIndent(blockchain, "", "  ")

	// fmt.Println(datas)
	enco := string(base58Encode(jsonString))
	deco := base58Decode([]byte(enco))
	fmt.Println(string(jsonString), jsonString, enco, deco, string(deco))
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

// You can do this by making a slice of interface{} type. For example:

// func main() {
//     arr := []interface{}{1, 2, "apple", true}
//     fmt.Println(arr)

//     // however, now you need to use type assertion access elements
//     i := arr[0].(int)
//     fmt.Printf("i: %d, i type: %T\n", i, i)

//     s := arr[2].(string)
//     fmt.Printf("b: %s, i type: %T\n", s, s)
// }

// for k, v := range p {
// 	switch c := v.(type) {
// 	case string:
// 	  fmt.Printf("Item %q is a string, containing %q\n", k, c)
// 	case float64:
// 	  fmt.Printf("Looks like item %q is a number, specifically %f\n", k, c)
// 	default:
// 	  fmt.Printf("Not sure what type item %q is, but I think it might be %T\n", k, c)
// 	}
//   }
