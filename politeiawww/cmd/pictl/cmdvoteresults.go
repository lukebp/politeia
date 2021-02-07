// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// cmdVoteResults retreives the cast votes for the provided proposal.
type cmdVoteResults struct {
	Args struct {
		Token string `positional-arg-name:"token"`
	} `positional-args:"true" required:"true"`
}

/*
// Execute executes the cmdVoteResults command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteResults) Execute(args []string) error {
	// Setup request
	vr := pi.VoteResults{
		Token: cmd.Args.Token,
	}

	// Send request. The request and response details are printed to
	// the console.
	err := shared.PrintJSON(vr)
	if err != nil {
		return err
	}
	vrr, err := client.VoteResults(vr)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(vrr)
	if err != nil {
		return err
	}

	return nil
}
*/

// voteResultsHelpMsg is printed to stdout by the help command.
const voteResultsHelpMsg = `voteresults "token"

Fetch vote results for the provided proposal.

Arguments:
1. token  (string, required)  Proposal censorship token
`