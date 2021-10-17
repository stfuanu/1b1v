package main

import (
	core "pro/core"
	api "pro/web"
)

func main() {
	// core.New()
	
	core.Genesisblock()
	// core.Printblockchain()
	// core.Newb()
	_ , _ , _ = core.Addnewblock("19yaXUBokMBzdqFex5qpZPwvV3CStnRVff", "19yaXUBokMBzdqFex5qpZPwvV3CStnRVff")
	_, _ , _ = core.Addnewblock("aty", "cand22")
	
	// _, _ = core.Addnewblock("a4u", "cand82")
	// _, _ = core.Addnewblock("ayeru", "cand72")
	// _, _ = core.Addnewblock("ayru", "cand42")
	// _, _ = core.Addnewblock("ayffu", "cand542")
	// _, _ = core.Addnewblock("ayeru", "cand52")
	// core.Addnewblock("new", "klsklaskl")
	core.PrintblockchainStdout()
	api.StartServer()
	
}

// curl -X POST -H "content-type: application/json"  http://localhost/vote/new -d "{\"address\": \"anu\",\"candidate\": \"Z\"}"
