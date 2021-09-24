package main

import (
	core "pro/core"
	api "pro/web"
)

func main() {

	
	core.Genesisblock()
	// core.Printblockchain()
	// core.Newb()
	_, _ = core.Addnewblock("anu", "cand1")
	_, _ = core.Addnewblock("ayu", "cand2")
	// core.Addnewblock("new", "klsklaskl")
	core.PrintblockchainStdout()
	api.StartServer()
	
}

// curl -X POST -H "content-type: application/json"  http://localhost/vote/new -d "{\"voterAddr\": \"anu\",\"candidateAddr\": \"Z\"}"
