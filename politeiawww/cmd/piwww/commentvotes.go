// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// CommentVotesCmd retreives like comment objects for
// the specified proposal from the provided user.
type CommentVotesCmd struct {
	Args struct {
		Token  string `positional-arg-name:"token"`  // Censorship token
		UserID string `positional-arg-name:"userid"` // User id
	} `positional-args:"true" required:"true"`

	// CLI flags
	Vetted   bool `long:"vetted" optional:"true"`
	Unvetted bool `long:"unvetted" optional:"true"`
}

// Execute executes the user comment likes command.
func (cmd *CommentVotesCmd) Execute(args []string) error {
	token := cmd.Args.Token
	userID := cmd.Args.UserID

	// Verify state
	var state pi.PropStateT
	switch {
	case cmd.Vetted && cmd.Unvetted:
		return fmt.Errorf("cannot use --vetted and --unvetted simultaneously")
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	case cmd.Vetted:
		state = pi.PropStateVetted
	default:
		return fmt.Errorf("must specify either --vetted or unvetted")
	}

	cvr, err := client.CommentVotes(pi.CommentVotes{
		Token:  token,
		State:  state,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	return shared.PrintJSON(cvr)
}

// commentVotesHelpMsg is the output for the help command when
// 'commentvotes' is specified.
const commentVotesHelpMsg = `commentvotes "token" "userid"

Get the provided user comment upvote/downvotes for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token
2. userid      (string, required)  User id

Flags:
  --vetted     (bool, optional)    Comment on vetted record.
  --unvetted   (bool, optional)    Comment on unvetted reocrd.
`
